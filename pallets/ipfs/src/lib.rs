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
use pallet_proxy::ProxyConfigState;

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
														  + pallet_proxy::Config
	{
		/// The Event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		/// the overarching call type
		type Call: From<Call<Self>>;
		/// the authority id used for sending signed txs
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
		/// Number of blocks between checks for ipfs daemon availability and configuration
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

	/// map substrate public key to ipfs public key
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
					}
					// else {
					// 	// check if identity verification success and data has been submitted
					// 	if let Err(e) = Self::ipfs_update_configs() {
					// 		log::error!("Encountered an error while attempting to update ipfs node config: {:?}", e);
					// 	}	
					// 	// if configuration succeeded, continue to swarm connection management
					// 	if let Err(e) = Self::ipfs_swarm_connection_management() {
					// 		log::error!("Encountered an error while managing swarm connections: {:?}", e);
					// 	}
					// }
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
            admin: <T::Lookup as StaticLookup>::Source,
            cid: Vec<u8>,
            id: T::AssetId,
            balance: T::Balance,
			dataspace_id: T::AssetId,
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
        /// * origin: a validator node
        /// * public_key: The IPFS node's public key
        /// * multiaddresses: A vector of multiaddresses associate with the public key
        ///
        #[pallet::weight(100)]
        pub fn submit_ipfs_identity(
            origin: OriginFor<T>,
            public_key: Vec<u8>,
            multiaddresses: Vec<OpaqueMultiaddr>,
        ) -> DispatchResult {
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

	/// verify if an ipfs daemon is running and if so, report its identity on chain
	/// 
	fn ipfs_verify_identity() -> Result<(), Error<T>> {
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

		// get pubkey
		let id = &json["ID"];
		let pubkey = id.clone().as_str().unwrap().as_bytes().to_vec();
		// get multiaddresses
		let addrs: Vec<Value> = serde_json::from_value(json["Addresses"].clone())
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
		// 1. get ipfs node id
		let id_res = match ipfs::identity() {
			Ok(res) => {
				log::info!("{:?}", res);
				res.body().collect::<Vec<u8>>()
			} 
			Err(e) => {
				return Err(Error::<T>::IpfsNotAvailable);
			}
		};

		// parse body as json
		let body = sp_std::str::from_utf8(&id_res).map_err(|_| Error::<T>::ResponseParsingFailure).unwrap();
		let json = ipfs::parse(body).map_err(|_| Error::<T>::ResponseParsingFailure).unwrap();

		// get pubkey
		let id = &json["ID"];
		let pubkey = id.clone().as_str().unwrap().as_bytes().to_vec();
		// 2. use id to get associated accountid
		match <SubstrateIpfsBridge::<T>>::get(&pubkey) {
			Some(acct_id) => {
				// 3. use accountid to get proxy prefs
				match <pallet_proxy::Pallet<T>>::proxies(&acct_id) {
					Some(preferences) => {
						// 4. Make calls to update ipfs node config
						// TODO: should create enum for the key: Datastore.StorageMax
						let key = "Datastore.StorageMax".as_bytes().to_vec();
						let val = format!("{}", preferences.storage_max_gb).as_bytes().to_vec();
						let storage_size_config_item = ipfs::IpfsConfigRequest{
							key: key.clone(),
							value: val.clone(),
							boolean: None,
							json: None,
						};
						ipfs::config_update(storage_size_config_item).map_err(|_| Error::<T>::ConfigUpdateFailure);
					},
					None => {
						log::info!("No preferences found!");
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

	// RPC endpoint implementations for data ingestion and ejection
	
	/// Acts as a permissioned gateway to the proxy node's IPFS instance
	/// 
	/// * byte_stream: A stream of bytes to be ingested
	/// * asset_id: the desired id to assign to the asset class after ingestion is complete
	/// * signature: The signature of the caller
	/// * signer: The account id of the caller
	/// * message: A signed message
	/// 
	pub fn handle_add_bytes(
		byte_stream: Bytes,
		asset_id: u32,
		signature: Bytes,
		signer: Bytes,
		message: Bytes,
	) -> Bytes
		where <T as pallet_assets::pallet::Config>::AssetId: From<u32> {
		// TODO: can probably replace signer with AccountId type
		// TODO: fail fast by checking that the signer is an authorized caller
		// TODO: allow proxy node to execute this logic: check if self is proxydsd
		let account_bytes: [u8; 32] = signer.to_vec().try_into().unwrap();
		let pubkey = Public::from_raw(account_bytes);
		// convert Bytes type to types needed for verification
        let sig: Signature = Signature::from_slice(signature.to_vec().as_ref()).unwrap();
		let msg: Vec<u8> = message.to_vec();

        // signature verification
		if sig.verify(msg.as_slice(), &pubkey) {
			// add bytes to ipfs
			let req = ipfs::IpfsAddRequest {
				bytes: byte_stream.to_vec(),
			};
			match ipfs::add(req) {
				Ok(res) => {
					let res_u8 = res.body().collect::<Vec<u8>>();
					let body = sp_std::str::from_utf8(&res_u8).map_err(|_| Error::<T>::ResponseParsingFailure).unwrap();
					let json = ipfs::parse(body).map_err(|_| Error::<T>::ResponseParsingFailure).unwrap();
					log::info!("{:?}", json["Size"]);
				},
				Err(e) => {
					return Bytes(Vec::new());
				}
			}
			// submit signed tx to create asset class
			let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
			if !signer.can_sign() {
				log::error!(
					"No local accounts available. Consider adding one via `author_insertKey` RPC.",
				);
			}
			// TODO: send signed tx
			// let results = signer.send_signed_transaction(|_account| { 
			// 	Call::submit_ipfs_add_results{
			// 		admin: admin.clone(),
			// 		cid: cid.clone(),
			// 		dataspace_id: dataspace_id.clone(),
			// 		id: id.clone(),
			// 		balance: balance.clone(),
			// 	}
			// });
		
			// for (_, res) in &results {
			// 	match res {
			// 		Ok(()) => log::info!("Submitted results successfully"),
			// 		Err(e) => log::error!("Failed to submit transaction: {:?}",  e),
			// 	}
			// }
			// Add bytes to offchain client
			return Bytes(Vec::new());
		}
		Bytes(Vec::new())
	}

	/// Placeholder for now, to be called by RPC
	pub fn handle_retrieve_bytes(asset_id: u32) -> Bytes 
		where <T as pallet_assets::pallet::Config>::AssetId: From<u32>{
		Bytes(Vec::new())
	}
}
