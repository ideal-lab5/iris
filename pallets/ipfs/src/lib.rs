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
//! This pallet contains the integration and configuration
//! with an external IPFS instance via the IPFS API endpoints.
//! 

#![cfg_attr(not(feature = "std"), no_std)]

mod mock;
mod tests;

pub mod ipfs;

use frame_support::{
	ensure,
	pallet_prelude::*,
	traits::{ Get, LockableCurrency },
};
use serde_json::Value;
use sp_runtime::offchain::OpaqueMultiaddr;
use scale_info::TypeInfo;
pub use pallet::*;
use sp_std::{
	str,
	vec::Vec,
	prelude::*
};
use sp_core::crypto::KeyTypeId;
use frame_system::{
	self as system, 
	ensure_signed,
	offchain::{
		Signer, SendSignedTransaction,
	}
};
use scale_info::prelude::format;
use iris_primitives::IngestionCommand;
use pallet_gateway::ProxyProvider;
use pallet_data_assets::{ResultsHandler, QueueManager};
use pallet_iris_proxy::OffchainKeyManager;

pub const LOG_TARGET: & str = "runtime::ipfs";

pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

pub mod crypto {
	use super::KEY_TYPE;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::app_crypto::{app_crypto, sr25519};
	use sp_runtime::{traits::Verify, MultiSignature, MultiSigner};
	use sp_std::convert::TryFrom;

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

/// config items that a node is allowed to configure
#[derive(Clone, PartialEq, Eq, RuntimeDebug)]
pub enum IpfsConfigKey {
	StorageMax,
}

impl AsRef<str> for IpfsConfigKey {
	fn as_ref(&self) -> &str {
		match *self {
			IpfsConfigKey::StorageMax => "Datastore.StorageMax",
		}
	}
}

#[derive(Encode, Decode, RuntimeDebug, TypeInfo, Default)]
pub struct Configuration {
	pub storage_config: u128,
	pub ready: bool,
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
														  + pallet_authorities::Config
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
		/// provides proxy nodes
		type ProxyProvider: pallet_gateway::ProxyProvider<Self::AccountId, Self::Balance>;
		/// provide queued requests to vote on
		type QueueManager: pallet_data_assets::QueueManager<Self::AccountId, Self::Balance>;
		/// provides asset metadata
		type MetadataProvider: pallet_data_assets::MetadataProvider<Self::AssetId>;
		/// handle results after executing a command
		type ResultsHandler: pallet_data_assets::ResultsHandler<Self, Self::AccountId, Self::AssetId, Self::Balance>;
		#[pallet::constant]
		type NodeConfigBlockDuration: Get<u32>;
		/// TODO: this really is a bad design.
		type OffchainKeyManager: pallet_iris_proxy::OffchainKeyManager<Self::AccountId>;
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

	/// track ipfs repo stats onchain
	/// for now, we just map accountid to actual storage size
	#[pallet::storage]
	#[pallet::getter(fn stats)]
	pub(super) type Stats<T: Config> = StorageMap<
		_, Blake2_128Concat, T::AccountId, u128, ValueQuery,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		IdentitySubmitted(T::AccountId),
		ConfigurationSyncSubmitted(T::AccountId),
		IngestionComplete(),
	}

	#[pallet::error]
	pub enum Error<T> {
		PublicKeyConversionFailure,
		InvalidPublicKey,
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
		NotAuthorized,
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		// The offchain worker here will act as the main coordination point for all offchain functions
		// that require a substrate acct id (as identified by ipfs pubkey)
		fn offchain_worker(block_number: T::BlockNumber) {
			// only validators are allowed to perform these permissioned offchain operations
			if sp_io::offchain::is_validator() {
				match Self::fetch_identity_json() {
					Ok(id_json) => {
						let id = &id_json["ID"];
						let pubkey = id.clone().as_str().unwrap().as_bytes().to_vec();
						match <SubstrateIpfsBridge::<T>>::get(pubkey) {
							Some(addr) => {
								if <pallet_authorities::Pallet<T>>::x25519_public_keys(addr.clone()).is_empty() {
									// should only happen once
									<pallet_authorities::Pallet<T>>::update_x25519();
										if let Err(e) = Self::ipfs_update_configs(addr.clone()) {
											log::error!("Encountered an error while attempting to update ipfs node config: {:?}", e);
										}
								}
								if block_number % T::NodeConfigBlockDuration::get().into() == 0u32.into() {
									if let Err(e) = Self::handle_ingestion_queue(addr.clone()) {
										log::error!("Encountered an error while attempting to process the ingestion queue: {:?}", e);
									}
									let authorities = <pallet_authorities::Pallet<T>>::validators();
									T::OffchainKeyManager::process_reencryption_requests(addr.clone());
									T::OffchainKeyManager::process_decryption_delegation(addr, authorities);
								} 
							},
							None => {
								// this will always happen the first time through the loop
								// we have fetched the IPFS node identity, but it hasn't been 
								// encoded on-chain yet. So we will wait until the next time this
								// logic executes, at which point it will be onchain
								log::info!("No identifiable ipfs-substrate association.");
								if let Err(e) = Self::ipfs_verify_identity() {
									log::error!("Encountered an error while attempting to verify ipfs node identity: {:?}", e);
								}
							}
						}
					},
					Err(_e) => {
						// log::error!("There is no reachable IPFS node {:?}", e);
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
        pub fn submit_ingestion_completed(
            origin: OriginFor<T>,
			cmd: IngestionCommand<T::AccountId, T::Balance>,
        ) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let queued_commands = T::QueueManager::ingestion_requests(who.clone());
			ensure!(queued_commands.contains(&cmd), Error::<T>::NotAuthorized);
			let new_origin = system::RawOrigin::Signed(who.clone()).into();
			let new_asset_id = T::ProxyProvider::next_asset_id(who);
			T::ResultsHandler::create_asset_class(new_origin, cmd, new_asset_id.into())?;
			Self::deposit_event(Event::IngestionComplete());
            Ok(())
        }

        /// Should only be callable by OCWs (TODO)
        /// Submit the results of an `ipfs identity` call to be stored on chain
        ///
        /// * origin: a validator node who is the controller for some stash
        /// * public_key: The IPFS node's public key
        /// * multiaddresses: A vector of multiaddresses associate with the public key
        ///
        #[pallet::weight(100_000)]
        pub fn submit_ipfs_identity(
            origin: OriginFor<T>,
            public_key: Vec<u8>,
            multiaddresses: Vec<OpaqueMultiaddr>,
        ) -> DispatchResult {
			// we assume that this is the controller
            let who = ensure_signed(origin)?;
			if <SubstrateIpfsBridge::<T>>::contains_key(public_key.clone()) {
				let existing_association = <SubstrateIpfsBridge::<T>>::get(public_key.clone()).unwrap();
				ensure!(who == existing_association, Error::<T>::InvalidPublicKey);
			}
			<BootstrapNodes::<T>>::insert(public_key.clone(), multiaddresses);
			<SubstrateIpfsBridge::<T>>::insert(public_key, who.clone());
			Self::deposit_event(Event::IdentitySubmitted(who));
            Ok(())
        }

		#[pallet::weight(100_000)]
		pub fn submit_config_complete(
			origin: OriginFor<T>,
			reported_storage_size: u128,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			<Stats<T>>::insert(who.clone(), reported_storage_size);
			Self::deposit_event(Event::ConfigurationSyncSubmitted(who));
			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {

	/// Fetch the identity of a locally running ipfs node and convert it to json
	/// TODO: could potentially move this into the ipfs.rs file?
	/// it really doesn't seem like a great idea to have to make this api call every single block
	/// I guess it's fine for now
	pub fn fetch_identity_json() -> Result<serde_json::Value, Error<T>> {
		let id_raw = Self::do_get_ipfs_id()?; 
		let body = sp_std::str::from_utf8(&id_raw).map_err(|_| Error::<T>::ResponseParsingFailure)?;
		let json = ipfs::parse(body).map_err(|_| Error::<T>::ResponseParsingFailure)?;
		Ok(json)
	}

	fn do_get_ipfs_id() -> Result<Vec<u8>, Error<T>> {
		// let local_storage = StorageValueRef::persistent(b"iris::ipfs");
		// if let Ok(Some(id_res)) = local_storage.get::<Vec<u8>>() {
		// 	Ok(id_res)
		// } else {
		match ipfs::identity() {
			Ok(res) => {
				let out = res.body().collect::<Vec<u8>>();
				Ok(out)
			} 
			Err(_e) => {
				Err(Error::<T>::IpfsNotAvailable)
			}
		}
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
			Call::submit_ipfs_identity {
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
	fn ipfs_update_configs(account: T::AccountId) -> Result<(), Error<T>> {
		match T::ProxyProvider::prefs(account) {
			// TODO: read from prefs...
			Some(_prefs) => {
				// for now, default to 50mb
				let val = format!("{}GB", 50).as_bytes().to_vec();
				// 4. Make calls to update ipfs node config
				let key = IpfsConfigKey::StorageMax.as_ref().as_bytes().to_vec();
				let storage_size_config_item = ipfs::IpfsConfigRequest{
					key,
					value: val,
					boolean: None,
					json: None,
				};
				ipfs::config_update(storage_size_config_item).map_err(|_| Error::<T>::ConfigUpdateFailure)?;
				let stat_response = ipfs::repo_stat().map_err(|_| Error::<T>::IpfsNotAvailable).unwrap();
				// 2. get actual available storage space
				if let Some(actual_storage) = stat_response["StorageMax"].clone().as_u64() {
					// 3. report result on chain
					let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
					if !signer.can_sign() {
						log::error!(
							"No local accounts available. Consider adding one via `author_insertKey` RPC.",
						);
					}
					let results = signer.send_signed_transaction(|_account| { 
						Call::submit_config_complete{
							reported_storage_size: actual_storage.into(),
						}
					});

					for (_, res) in &results {
						match res {
							Ok(()) => log::info!("Submitted results successfully"),
							Err(e) => log::error!("Failed to submit transaction: {:?}",  e),
						}
					}
				}
			},
			None => {
				// TODO: Should be an error
				log::info!("The node is not properly configured: call gateway_declareProxy.");
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
    fn _ipfs_swarm_connection_management(_addr: T::AccountId) -> Result<(), Error<T>> {
		// connect to a bootstrap node if one is available
		// not yet implemented
        Ok(())
    }

	/// process requests to ingest data from offchain clients
	/// This function fetches data from offchain clients and ingests it into IPFS
	/// it finally sends a signed tx to create an asset class on behalf of the caller
	fn handle_ingestion_queue(account: T::AccountId) -> Result<(), Error<T>> {
		let queued_commands = T::QueueManager::ingestion_requests(account);
		log::info!("Processing {:?} items in the ingestion queue", queued_commands.len());
		for cmd in queued_commands.iter() {
			let cid = cmd.cid.clone();
			ipfs::get(&cid.clone()).map_err(|_| Error::<T>::InvalidCID)?;
			
			let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
			if !signer.can_sign() {
				log::error!(
					"No local accounts available. Consider adding one via `author_insertKey` RPC.",
				);
			}
			let results = signer.send_signed_transaction(|_acct| { 
				Call::submit_ingestion_completed {
					cmd: cmd.clone(),
				}
			});
		
			for (_, res) in &results {
				match res {
					Ok(()) => log::info!("Submitted results successfully"),
					Err(e) => log::error!("Failed to submit transaction: {:?}",  e),
				}
			}
		}
		Ok(())
	}
}




