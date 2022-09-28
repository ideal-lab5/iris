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
	offchain::{
		http,
		storage::StorageValueRef,
	},
	traits::StaticLookup,
};

use umbral_pre::*;

use rand_chacha::{
	ChaCha20Rng,
	rand_core::SeedableRng,
};

use crypto_box::{
    aead::{Aead, AeadCore, Payload},
	SalsaBox, PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, Nonce,
};

use scale_info::prelude::format;
use iris_primitives::IngestionCommand;
use pallet_gateway::ProxyProvider;
use pallet_data_assets::{MetadataProvider, ResultsHandler, QueueProvider};
use pallet_ipfs_primitives::{IpfsResult, IpfsError};

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

/// keys that a proxy node is allowed to configure
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
		type QueueProvider: pallet_data_assets::QueueProvider<Self::AccountId, Self::AssetId, Self::Balance>;
		/// provides asset metadata
		type MetadataProvider: pallet_data_assets::MetadataProvider<Self::AssetId>;
		/// provides ejection commands 
		// type EjectionCommandDelegator: pallet_authorization::EjectionCommandDelegator<Self::AccountId, Self::AssetId>;
		/// handle results after executing a command
		type ResultsHandler: pallet_data_assets::ResultsHandler<Self, Self::AccountId, Self::Balance>;
		// TODO: this should be read from runtime storage instead
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
		PublicKeyConversionFailure,
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
		fn offchain_worker(block_number: T::BlockNumber) {
			if block_number % T::NodeConfigBlockDuration::get().into() == 0u32.into() {
				if sp_io::offchain::is_validator() {
					if let Err(e) = Self::ipfs_verify_identity() {
						log::error!("Encountered an error while attempting to verify ipfs node identity: {:?}", e);
					} else {
						// TODO: properly handle error
						let id_json = Self::fetch_identity_json().expect("IPFS should be reachable");
						// get pubkey
						let id = &id_json["ID"];
						let pubkey = id.clone().as_str().unwrap().as_bytes().to_vec();
						match <SubstrateIpfsBridge::<T>>::get(&pubkey) {
							Some(addr) => { 
								if let Err(e) = Self::ipfs_update_configs(addr.clone()) {
									log::error!("Encountered an error while attempting to update ipfs node config: {:?}", e);
								} 
								if let Err(e) = Self::handle_ingestion_queue(addr.clone()) {
									log::error!("Encountered an error while attempting to process the ingestion queue: {:?}", e);
								}
								if let Err(e) = Self::process_capsule_recovery_requests(addr.clone()) {
									log::error!("Encountered an error while attempting to recover capsule fragments: {:?}", e);
								}
							},
							None => {
								// TODO: Should be an error
								log::info!("No identifiable ipfs-substrate association");
							}
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
        pub fn submit_ingestion_completed(
            origin: OriginFor<T>,
			cmd: IngestionCommand<T::AccountId, T::Balance>,
        ) -> DispatchResult {
			let who = ensure_signed(origin)?;
			let queued_commands = T::QueueProvider::ingestion_requests(who.clone());
			ensure!(queued_commands.contains(&cmd), Error::<T>::NotAuthorized);
			// we need to find the puiblic key as well..
			let new_origin = system::RawOrigin::Signed(who.clone()).into();
			T::ResultsHandler::create_asset_class(new_origin, cmd)?;
			// emit event
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
			if <SubstrateIpfsBridge::<T>>::contains_key(public_key.clone()) {
				let existing_association = <SubstrateIpfsBridge::<T>>::get(public_key.clone()).unwrap();
				ensure!(who == existing_association, Error::<T>::InvalidMultiaddress);
			}
			<BootstrapNodes::<T>>::insert(public_key.clone(), multiaddresses.clone());
			<SubstrateIpfsBridge::<T>>::insert(public_key.clone(), who.clone());
			Self::deposit_event(Event::IdentitySubmitted(who.clone()));
            Ok(())
        }

		#[pallet::weight(100)]
		pub fn submit_config_complete(
			origin: OriginFor<T>,
			reported_storage_size: u128,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			<Stats<T>>::insert(who.clone(), reported_storage_size);
			Self::deposit_event(Event::ConfigurationSyncSubmitted(who.clone()));
			Ok(())
		}

		#[pallet::weight(100)]
		pub fn submit_recovered_capsule_fragment(
			origin: OriginFor<T>,
			data_consumer: T::AccountId,
			asset_id: T::AssetId,
			encrypted_cfrag_data: iris_primitives::EncryptedFragment,
		) -> DispatchResult {
			// this really doesn't seem appropriate to place here, whatever for now it's fine
			T::QueueProvider::add_verified_capsule(data_consumer, asset_id, encrypted_cfrag_data);
			// deposit event
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
	pub fn fetch_identity_json() -> Result<serde_json::Value, Error<T>> {
		let cached_info = StorageValueRef::persistent(b"ipfs:id");
		let id_res = match ipfs::identity() {
			Ok(res) => {
				res.body().collect::<Vec<u8>>()
			} 
			Err(e) => {
				return Err(Error::<T>::IpfsNotAvailable);
			}
		};

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
	fn ipfs_update_configs(account: T::AccountId) -> Result<(), Error<T>> {
		match T::ProxyProvider::prefs(account.clone()) {
			Some(prefs) => {
				let val = format!("{}", prefs.storage_max_gb).as_bytes().to_vec();
				// 4. Make calls to update ipfs node config
				let key = IpfsConfigKey::StorageMax.as_ref().as_bytes().to_vec();
				let storage_size_config_item = ipfs::IpfsConfigRequest{
					key: key.clone(),
					value: val.clone(),
					boolean: None,
					json: None,
				};
				ipfs::config_update(storage_size_config_item).map_err(|_| Error::<T>::ConfigUpdateFailure);
				let stat_response = ipfs::repo_stat().map_err(|_| Error::<T>::IpfsNotAvailable).unwrap();
				// 2. get actual available storage space
				match stat_response["SizeStat.StorageMax"].clone().as_u64() {
					Some(actual_storage) => {
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
					},
					None => {
						// do nothing for now
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
    fn ipfs_swarm_connection_management(addr: T::AccountId) -> Result<(), Error<T>> {
		// connect to a bootstrap node if one is available
        Ok(())
    }

	/// process requests to ingest data from offchain clients
	/// This function fetches data from offchain clients and ingests it into IPFS
	/// it finally sends a signed tx to create an asset class on behalf of the caller
	fn handle_ingestion_queue(account: T::AccountId) -> Result<(), Error<T>> {
		let queued_commands = T::QueueProvider::ingestion_requests(account);
		for cmd in queued_commands.iter() {
			let owner = cmd.owner.clone();
			let cid = cmd.cid.clone();
			// must disconnect from all current peers and makes oneself undiscoverable
			// but since we aren't connected to anyone else... this is fine.
			// connect to multiaddress from request
			ipfs::connect(&cmd.multiaddress.clone()).map_err(|_| Error::<T>::InvalidMultiaddress);
			// ipfs get cid 
			let response = ipfs::get(&cid.clone()).map_err(|_| Error::<T>::InvalidCID);
			// TODO: remove these logs
			log::info!("Fetched data with CID {:?} from multiaddress {:?}", cid.clone(), cmd.multiaddress.clone());
			log::info!("{:?}", response);
			// disconnect from multiaddress
			ipfs::disconnect(&cmd.multiaddress.clone()).map_err(|_| Error::<T>::InvalidMultiaddress);
			// Q: is there some way we can verify that the data we received is from the correct maddr? is that needed?
			let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
			if !signer.can_sign() {
				log::error!(
					"No local accounts available. Consider adding one via `author_insertKey` RPC.",
				);
			}
			let results = signer.send_signed_transaction(|_acct| { 
				Call::submit_ingestion_completed{
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

	fn process_capsule_recovery_requests(account: T::AccountId) -> Result<(), Error<T>> {
		let capsule_recovery_requests = T::QueueProvider::get_capsule_recovery_requests(account.clone());

		let secret_storage = StorageValueRef::persistent(b"iris::secret");
		if let Ok(Some(local_sk)) = secret_storage.get::<[u8;32]>() {
			let secret_key: BoxSecretKey = BoxSecretKey::from(local_sk);
			for cap_recovery_request in capsule_recovery_requests {

				let pk = cap_recovery_request.ciphertext_encryption_pk;

				// for each public key, find the corresponding kfrag assigned to you
				let encrypted_kfrag_data = T::QueueProvider::get_kfrags(pk.clone(), account.clone()).unwrap();

				// convert to PublicKey
				let pubkey_slice_32 = iris_primitives::slice_to_array_32(encrypted_kfrag_data.public_key.as_slice()).unwrap();
				let public_key = BoxPublicKey::from(*pubkey_slice_32);
				// decrypt the kfrag
				let kfrag = Self::recover_encrypted_kfrag(
					public_key, secret_key.clone(), encrypted_kfrag_data.ciphertext, encrypted_kfrag_data.nonce
				);

				// verify kfrag
				let mut rng = ChaCha20Rng::seed_from_u64(31u64);
				let sk = SecretKey::random_with_rng(rng.clone());
				let signer = umbral_pre::Signer::new(sk.clone());
				let verifying_pk = signer.verifying_key();
				
				// now that we have they keyfrag, we can proceed to recover capsule frag
				// TODO: unsafe
				let pk_umbral = PublicKey::from_bytes(&pk).unwrap();
				let secret_data = T::QueueProvider::get_capsule(pk.clone()).unwrap();
				let capsule = Capsule::from_bytes(&secret_data.sk_capsule).unwrap();
				// 1. verify kfrag
				let verified_kfrag = kfrag.verify(&verifying_pk, Some(&pk_umbral), Some(&sk.public_key())).unwrap();
				let verified_cfrag = reencrypt_with_rng(&mut rng, &capsule, verified_kfrag);
				let cfrag_bytes = verified_cfrag.to_array().as_slice().to_vec();
				// now that we have the cfrag bytes, we need to encrypt the bytes for the requested account
				// this encryption will be done with cryptobox, not umbral
				// so now we need a cryptobox public key of the data owner						
				// for this, we can even generate new keys.. but we don't need to so nvm


				let consumer_ephemeral_pubkey_slice_32 = iris_primitives::slice_to_array_32(cap_recovery_request.capsule_encryption_pk.as_slice()).unwrap();
				let ephemeral_public_key = BoxPublicKey::from(*consumer_ephemeral_pubkey_slice_32);
				// fetch crypto_box pubkey of recipient (data consumer)
				let encrypted_cfrag_data = iris_primitives::encrypt_crypto_box(
					ephemeral_public_key,
					secret_key.clone(),
					cfrag_bytes,
				);
				
				let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
				if !signer.can_sign() {
					log::error!(
						"No local accounts available. Consider adding one via `author_insertKey` RPC.",
					);
				}
				let results = signer.send_signed_transaction(|_acct| { 
					Call::submit_recovered_capsule_fragment {
						data_consumer: cap_recovery_request.caller.clone(),
						asset_id: cap_recovery_request.asset_id,
						encrypted_cfrag_data: encrypted_cfrag_data.clone(),
					}
				});
			
				for (_, res) in &results {
					match res {
						Ok(()) => log::info!("Submitted results successfully"),
						Err(e) => log::error!("Failed to submit transaction: {:?}",  e),
					}
				}
			}	
		}

		
		Ok(())
	}

	fn recover_encrypted_kfrag(
		public_key: BoxPublicKey,
		secret_key: BoxSecretKey, 
		ciphertext_bytes: Vec<u8>,
		nonce_bytes: Vec<u8>,
	) -> KeyFrag {
		let salsa_box = SalsaBox::new(&public_key, &secret_key);
		// GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>, B0>>
		let gen_array = generic_array::GenericArray::clone_from_slice(nonce_bytes.as_slice());
		let plaintext = salsa_box.decrypt(&gen_array, Payload {
			msg: &ciphertext_bytes,
			aad: b"".as_ref(),
		}).unwrap();
		// convert to KeyFragment (TODO: this is insecure)
		KeyFrag::from_bytes(plaintext).unwrap()
	}

	// fn handle_ejection_queue() -> Result<(), Error<T>> {
	// 	let id_json = Self::fetch_identity_json()?;
	// 	// get pubkey
	// 	let id = &id_json["ID"];
	// 	let pubkey = id.clone().as_str().unwrap().as_bytes().to_vec();
	// 	match <SubstrateIpfsBridge::<T>>::get(&pubkey) {
	// 		// When node elections implemented => acct id will be used to get assigned reqs
	// 		Some(acct_id) => {
	// 			let queued_commands = T::EjectionCommandDelegator::ejection_commands(acct_id);
	// 			for cmd in queued_commands.iter() {
	// 				let caller = cmd.caller.clone();
	// 				let asset_id = cmd.asset_id.clone();
	// 				match T::MetadataProvider::get(asset_id.clone()) {
	// 					Some(metadata) => {
	// 						let cid = metadata.cid;

	// 						let data = match ipfs::cat(&cid.clone()) {
	// 							Ok(res) => {
	// 								res.body().collect::<Vec<u8>>()
	// 							} 
	// 							Err(e) => {
	// 								return Err(Error::<T>::IpfsNotAvailable);
	// 							}
	// 						};

	// 						log::info!("FETCHED DATA: {:?}", data);
	// 						// now need to re-encrypt and add to IPFS
	// 						let reencrypted = Self::reencrypt_data(data);
	// 						log::info!("Reencrypted and publishing new CID");
	// 						// add to IPFS
	// 						let _ipfs_add_res = ipfs::add(ipfs::IpfsAddRequest{
	// 							bytes: reencrypted,
	// 						}).map_err(|e| Error::<T>::IpfsError).ok().unwrap();

	// 						let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
	// 						if !signer.can_sign() {
	// 							log::error!(
	// 								"No local accounts available. Consider adding one via `author_insertKey` RPC.",
	// 							);
	// 						}
	// 						// TODO:
	// 						let results = signer.send_signed_transaction(|_acct| { 
	// 							Call::submit_data_ready{
									
	// 							}
	// 						});
						
	// 						for (_, res) in &results {
	// 							match res {
	// 								Ok(()) => log::info!("Submitted results successfully"),
	// 								Err(e) => log::error!("Failed to submit transaction: {:?}",  e),
	// 							}
	// 						}
	// 					}, 
	// 					None => {
	// 						// do nothing
	// 					}
	// 				}
	// 			}
	// 		},
	// 		None => {
	// 			// do nothing for now
	// 			log::info!("No identifiable substrate-ipfs association");
	// 		}
	// 	}
	// 	Ok(())
	// }

	fn reencrypt_data(data: Vec<u8>) -> Vec<u8> {
		data
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
