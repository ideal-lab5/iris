// This file is part of Iris.
//
// Copyright (C) 2022 Ideal Labs.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! # IPFS Pallet
//!
//! @author driemworks
//! 
//! ## Description 
//! 
//! This pallet contains the core integration and configuration
//! with an external IPFS instance, as interfaced with via the IPFS 
//! RPC endpoints.
//! 

#![cfg_attr(not(feature = "std"), no_std)]

mod mock;
mod tests;

pub mod ipfs;

use frame_support::{
	ensure,
	pallet_prelude::*,
	traits::{
		EstimateNextSessionRotation, Get,
		ValidatorSet, ValidatorSetWithIdentification,
		Currency, LockableCurrency,
	},
};
use log;
use serde_json::Value;

use scale_info::TypeInfo;
pub use pallet::*;
use sp_runtime::traits::{Convert, Verify, Zero};
use sp_staking::offence::{Offence, OffenceError, ReportOffence};
use sp_std::{
	collections::{btree_set::BTreeSet, btree_map::BTreeMap},
	str,
	vec::Vec,
	prelude::*
};
use sp_core::{
    offchain::{
        OpaqueMultiaddr, StorageKind,
    },
	Bytes,
	crypto::KeyTypeId,
	sr25519::{Signature, Public},
};
use frame_system::{
	self as system, 
	ensure_signed,
	offchain::{
		SendSignedTransaction,
		Signer,
	}
};
use sp_runtime::{
	offchain::http,
	traits::StaticLookup,
};
use scale_info::prelude::format;
use pallet_data_assets::DataCommand;
use pallet_proxy::ProxyConfigState;
use pallet_ipfs_primitives::{IpfsResult, IpfsError};
use offchain_client::interface;

pub const LOG_TARGET: &'static str = "runtime::proxy";

pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

pub mod crypto {
	// use crate::KEY_TYPE;
	use sp_core::crypto::KeyTypeId;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::app_crypto::{app_crypto, sr25519};
	use sp_runtime::{traits::Verify, MultiSignature, MultiSigner};
	use sp_std::convert::TryFrom;

	pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;
	// implemented for runtime
	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}

	// implemented for mock runtime in test
	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
		for TestAuthId
	{
		type RuntimeAppPublic = Public;
		type GenericSignature = sp_core::sr25519::Signature;
		type GenericPublic = sp_core::sr25519::Public;
	}
}

type BalanceOf<T> = <T as pallet_assets::Config>::Balance;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::{
		pallet_prelude::*,
		offchain::{
			AppCrypto,
			CreateSignedTransaction,
		}
	};

	/// Configure the pallet by specifying the parameters and types on which it
	/// depends.
	/// TODO: reafactor so that we can read config-ready proxy nodes through runtime config
	#[pallet::config]
	pub trait Config: CreateSignedTransaction<Call<Self>> + frame_system::Config 
														  + pallet_assets::Config
														  + pallet_data_assets::Config
														  + pallet_proxy::Config
	{
		/// The Event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		/// the overarching call type
		type Call: From<Call<Self>>;
		/// the authority id used for sending signed txs
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
		/// Number of blocks between checks for ipfs daemon availability and configuration
		/// the currency used by the pallet
		type Currency: LockableCurrency<Self::AccountId>;
		#[pallet::constant]
		type NodeConfigBlockDuration: Get<u32>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

    /// map the ipfs public key to a list of multiaddresses
    #[pallet::storage]
    #[pallet::getter(fn bootstrap_nodes)]
    pub(super) type BootstrapNodes<T: Config> = StorageMap<
        _, Blake2_128Concat, Vec<u8>, Vec<OpaqueMultiaddr>, ValueQuery,
    >;

	/// map ipfs public key to substrate account id
	/// note: this will be the 'stash' account id, not the controller id
	#[pallet::storage]
	#[pallet::getter(fn substrate_ipfs_bridge)]
	pub(super) type SubstrateIpfsBridge<T: Config> = StorageMap<
		_, Blake2_128Concat, Vec<u8>, T::AccountId,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		IdentitySubmitted(T::AccountId),
	}

	
	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		/// Validate unsigned call to this module.
		///
		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			// if let Call::submit_rpc_ready { .. } = call {
			// 	Self::validate_transaction_parameters()
			// }
			if let Call::submit_ipfs_identity{ .. } = call {
				Self::validate_transaction_parameters()
			} else {
				InvalidTransaction::Call.into()
			}
		}
	}

	#[pallet::error]
	pub enum Error<T> {
		/// The specified multiaddress is invalid (could not be encoded as utf8)
		InvalidMultiaddress,
		/// The specified CID is invalid (could not be encoded as utf8)
		InvalidCID,
		/// An error occurred while communicated with IPFS
		IpfsError,
		/// an Ipfs daemon is not running or is unreachable
		IpfsNotAvailable,
		/// failed to parse the response body -> maybe temp 
		ResponseParsingFailure,
		/// failure when calling the /config endpoint to update config
		ConfigUpdateFailure,
		InvalidSigner,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(block_number: T::BlockNumber) {
			// every 100 blocks
			if block_number % T::NodeConfigBlockDuration::get().into() == 0u32.into() {
				if sp_io::offchain::is_validator() {
					if let Err(e) = Self::ipfs_verify_identity() {
						log::error!("Encountered an error while attempting to verify ipfs node identity: {:?}", e);
					} 
					if let Err(e) = Self::ipfs_update_configs() {
						log::error!("Encountered an error while attempting to update ipfs node config: {:?}", e);
					} else {
						if let Err(e) = Self::handle_ingestion_queue() {
							log::error!("Encountered an error while attempting to process the ingestion queue: {:?}", e);
						}
					}
				}
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {

        /// submits IPFS results on chain and creates new ticket config in runtime storage
        ///
        /// * `admin`: The admin account
        /// * `cid`: The cid generated by the OCW
        /// * `id`: The AssetId (passed through from the create_storage_asset call)
        /// * `balance`: The balance (passed through from the create_storage_asset call)
        ///
        #[pallet::weight(100)]
        pub fn submit_ipfs_add_results(
            origin: OriginFor<T>,
			// admin: <T::Lookup as StaticLookup>::Source,
			admin: T::AccountId,
            cid: Vec<u8>,
            id: T::AssetId,
			dataspace_id: T::AssetId,
            balance: T::Balance,
        ) -> DispatchResult {
			// let who = ensure_signed(origin)?;
			// let new_origin = system::RawOrigin::Signed(who.clone()).into();
			// creates the asset class
            // <pallet_data_assets::Pallet<T>>::submit_ipfs_add_results(
			// 	new_origin,
			// 	admin,
			// 	cid,
			// 	dataspace_id,
			// 	id,
			// 	balance,
			// )?;
            Ok(())
        }

        /// Should only be callable by OCWs (TODO)
        /// Submit the results of an `ipfs identity` call to be stored on chain
        ///
        /// * origin: a validator node who is the controller for some stash
        /// * public_key: The IPFS node's public key
        /// * multiaddresses: A vector of multiaddresses associate with the public key
        ///
        #[pallet::weight(100)]
        pub fn submit_ipfs_identity(
            origin: OriginFor<T>,
            public_key: Vec<u8>,
            multiaddresses: Vec<OpaqueMultiaddr>,
        ) -> DispatchResult {
			// we assume that this is the controller
            let who = ensure_signed(origin)?;
			// check if the proxy node is marked for configuration
			// if not, then do not proceed
			match <pallet_proxy::Pallet<T>>::proxy_config_status(&who) {
				Some(result) => {
					if result == ProxyConfigState::Unconfigured {
						if <SubstrateIpfsBridge::<T>>::contains_key(public_key.clone()) {
							let existing_association = <SubstrateIpfsBridge::<T>>::get(public_key.clone()).unwrap();
							ensure!(who == existing_association, Error::<T>::InvalidMultiaddress);
						}
						<BootstrapNodes::<T>>::insert(public_key.clone(), multiaddresses.clone());
						<SubstrateIpfsBridge::<T>>::insert(public_key.clone(), who.clone());
						<pallet_proxy::Pallet<T>>::update_proxy_state(who.clone(), ProxyConfigState::Identified);
						Self::deposit_event(Event::IdentitySubmitted(who.clone()));
					}
				},
				None => {
					return Ok(())
				}
			}
            Ok(())
        }
	}
}

impl<T: Config> Pallet<T> {

	fn validate_transaction_parameters() -> TransactionValidity {
		ValidTransaction::with_tag_prefix("iris")
			.longevity(5)
			.propagate(true)
			.build()
	}

	/// Fetch the identity of a locally running ipfs node and convert it to json
	/// TODO: could potentially move this into the ipfs.rs file
	fn fetch_identity_json() -> Result<serde_json::Value, Error<T>> {
		let id_res = match ipfs::identity() {
			Ok(res) => {
				log::info!("{:?}", res);
				res.body().collect::<Vec<u8>>()
			} 
			Err(e) => {
				return Err(Error::<T>::IpfsNotAvailable);
			}
		};

		// parse body
		let body = sp_std::str::from_utf8(&id_res).map_err(|_| Error::<T>::ResponseParsingFailure).unwrap();
		let json = ipfs::parse(body).map_err(|_| Error::<T>::ResponseParsingFailure).unwrap();
		Ok(json)
	}

	/// verify if an ipfs daemon is running and if so, report its identity on chain
	/// 
	fn ipfs_verify_identity() -> Result<(), Error<T>> {
		let id_json = Self::fetch_identity_json()?;
		// get pubkey
		let id = &id_json["ID"];
		let pubkey = id.clone().as_str().unwrap().as_bytes().to_vec();
		// get multiaddresses
		let addrs: Vec<Value> = serde_json::from_value(id_json["Addresses"].clone())
			.map_err(|_| Error::<T>::ResponseParsingFailure).unwrap();
		let addrs_vec: Vec<_> = addrs.iter()
			.map(|x| OpaqueMultiaddr(x.as_str().unwrap().as_bytes().to_vec()))
			.collect();
		// submit extrinsic
		let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			log::error!(
				"No local accounts available. Consider adding one via `author_insertKey` RPC.",
			);
		}
		let results = signer.send_signed_transaction(|_account| { 
			Call::submit_ipfs_identity{
				public_key: pubkey.clone(),
				multiaddresses: addrs_vec.clone(),
			}
		});
	
		for (_, res) in &results {
			match res {
				Ok(()) => log::info!("Submitted results successfully"),
				Err(e) => log::error!("Failed to submit transaction: {:?}",  e),
			}
		}
		Ok(())
	}

	/// update the running ipfs daemon's configuration to be in sync
	/// with the latest on-chain valid configuration values
	/// 
	fn ipfs_update_configs() -> Result<(), Error<T>> {
		let id_json = Self::fetch_identity_json()?;
		// get pubkey
		let id = &id_json["ID"];
		let pubkey = id.clone().as_str().unwrap().as_bytes().to_vec();
		// 2. use id to get associated 
		// TODO: cleanup these nested match statements: not very pretty
		match <SubstrateIpfsBridge::<T>>::get(&pubkey) {
			Some(controller_acct_id) => {

				match <pallet_proxy::Pallet<T>>::ledger(&controller_acct_id) {
					Some(staking_ledger) => {
						let stake = staking_ledger.active;
						let stake_primitive = TryInto::<u128>::try_into(stake).ok();
						let val = format!("{}", stake_primitive.unwrap()).as_bytes().to_vec();
						// 4. Make calls to update ipfs node config
						let key = "Datastore.StorageMax".as_bytes().to_vec();
						let storage_size_config_item = ipfs::IpfsConfigRequest{
							key: key.clone(),
							value: val.clone(),
							boolean: None,
							json: None,
						};
						ipfs::config_update(storage_size_config_item).map_err(|_| Error::<T>::ConfigUpdateFailure);		
					}
					None => {
						log::info!("No tokens staked: invalid proxy node");
					}
				}
			},
			None => {
				log::info!("No identifiable ipfs-substrate association");
			}
		}
		Ok(())
	}
	
	/// manage connection to the iris ipfs swarm
    ///
    /// If the node is already a bootstrap node, do nothing. Otherwise submits a signed tx 
    /// containing the public key and multiaddresses of the embedded ipfs node.
    /// 
    /// Returns an error if communication with IPFS fails
    fn ipfs_swarm_connection_management() -> Result<(), Error<T>> {
		// connect to a bootstrap node if one is available
        Ok(())
    }

	/// process requests to ingest data from offchain clients
	/// This function fetches data from offchain clients and ingests it into IPFS
	/// it finally sends a signed tx to create an asset class on behalf of the caller
	fn handle_ingestion_queue() -> Result<(), Error<T>> {
		// get IPFS node id and from there get the associated substrate address
		let id_json = Self::fetch_identity_json()?;
		// get pubkey
		let id = &id_json["ID"];
		let pubkey = id.clone().as_str().unwrap().as_bytes().to_vec();
		// 2. use id to get associated accountid: This will be important later.. for now the pubkey is unused
		match <SubstrateIpfsBridge::<T>>::get(&pubkey) {
			// When node elections implemented => acct id will be used to get assigned reqs
			Some(acct_id) => {
				// if there are no commands, then stop
				let commands = <pallet_proxy::Pallet<T>>::ingestion_processing_queue(&acct_id);
				let len = commands.len();
				if len != 0 {
					log::info!("IPFS: {} entr{} in the data queue", len, if len == 1 { "y" } else { "ies" });
				}
				// 1. loop over the commands that are assigned to that address (for now, just loop over all)
				for cmd in commands.into_iter() {
					// Fetch from OCC: TODO
					// this should let you fetch from another node's OCC
					// we will need to make an RPC call to fetch the data
					let data: Vec<u8> = offchain_client::interface::read(cmd.occ_id);
					// Add to IPFS
					let ipfs_add_request = ipfs::IpfsAddRequest{ bytes: data };
					match ipfs::add(ipfs_add_request) {
						Ok(res) => {
							// parse CID
							let res_u8 = res.body().collect::<Vec<u8>>();
							let body = sp_std::str::from_utf8(&res_u8).map_err(|_| Error::<T>::ResponseParsingFailure).unwrap();
							let json = ipfs::parse(body).map_err(|_| Error::<T>::ResponseParsingFailure).unwrap();
							let raw_cid = &json["Hash"];
							let cid = raw_cid.clone().as_str().unwrap().as_bytes().to_vec();
							// Report results on chain
							let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
							if !signer.can_sign() {
								log::error!(
									"No local accounts available. Consider adding one via `author_insertKey` RPC.",
								);
							}
							let results = signer.send_signed_transaction(|_account| { 
								Call::submit_ipfs_add_results{
									admin: cmd.owner.clone(),
									cid: cid.clone(),
									id: cmd.asset_id.clone(),
									dataspace_id: cmd.dataspace_id.clone(),
									balance: cmd.balance.clone(),
								}
							});
						
							for (_, res) in &results {
								match res {
									Ok(()) => log::info!("Submitted results successfully"),
									Err(e) => log::error!("Failed to submit transaction: {:?}",  e),
								}
							}
						},
						Err(e) => {
							return Err(Error::<T>::IpfsError);
						},
					}
				}
			},
			None => {
				// do nothing for now
			}
		}
		Ok(())
	}

	// RPC endpoint implementations for data ingestion and ejection
	
	/// Acts as a permissioned gateway to the proxy node's IPFS instance
	/// 
	/// * byte_stream: A stream of bytes to be ingested
	/// * asset_id: the desired id to assign to the asset class after ingestion is complete
	/// * signature: The signature of the caller
	/// * signer: The account id of the caller
	/// * message: A signed message
	/// TODO: abstract this into smaller functions
	pub fn handle_add_bytes(
		byte_stream: Bytes,
		asset_id: u32,
		dataspace_id: u32,
		balance: BalanceOf<T>,
		signature: Bytes,
		signer: Bytes,
		message: Bytes,
	) -> IpfsResult
		where <T as pallet_assets::pallet::Config>::AssetId: From<u32> {
		let bytes_vec: Vec<u8> = byte_stream.to_vec();
		offchain_client::interface::write(bytes_vec);
		IpfsResult{
			response: Bytes(Vec::new()),
			error: None,
		}
	}

	/// Placeholder for now, to be called by RPC
	pub fn handle_retrieve_bytes(asset_id: u32) -> Bytes 
		where <T as pallet_assets::pallet::Config>::AssetId: From<u32> {
		// TODO: map asset id to occ id -> store in metadata
		// let data: Vec<u8> = offchain_client::interface::read(occ_id);
		Bytes(Vec::new())
	}
}
