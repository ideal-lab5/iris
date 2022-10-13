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
		AppCrypto, CreateSignedTransaction, SendUnsignedTransaction, SignedPayload, SubmitTransaction, Signer, SendSignedTransaction,
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

use scale_info::prelude::string::ToString;
use scale_info::prelude::format;
use iris_primitives::{IngestionCommand, EncryptedFragment};
use pallet_gateway::ProxyProvider;
use pallet_data_assets::{MetadataProvider, ResultsHandler, QueueProvider};
use pallet_ipfs_primitives::{IpfsResult, IpfsError};

pub const LOG_TARGET: &'static str = "runtime::proxy";

pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

pub mod crypto {
	use super::KEY_TYPE;
	use sp_core::crypto::KeyTypeId;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::app_crypto::{app_crypto, sr25519};
	use sp_runtime::{traits::Verify, MultiSignature, MultiSigner};
	use sp_std::convert::TryFrom;

	// pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

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
		IngestionComplete(),
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
		InsufficientAuthorities,
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
								// proxy nodes generate kfrags
								if let Err(e) = Self::proxy_process_kfrag_generation_requests(addr.clone()) {
									log::error!("Encountered an error while attempting to generate key fragments: {:?}", e);
								}
								if let Err(e) = Self::kfrag_holder_process_reencryption_requests(addr.clone()) {
									log::error!("Encountered an error while attempting to reencrypt a key fragments: {:?}", e);
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
				ensure!(who == existing_association, Error::<T>::InvalidPublicKey);
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
		pub fn submit_capsule_fragment(
			origin: OriginFor<T>,
			data_consumer: T::AccountId,
			public_key: Vec<u8>,
			encrypted_cfrag_data: iris_primitives::EncryptedFragment,
		) -> DispatchResult {
			// this really doesn't seem appropriate to place here, whatever for now it's fine
			T::QueueProvider::add_verified_capsule_frag(data_consumer, public_key, encrypted_cfrag_data);
			// deposit event
			Ok(())
		}

		// TODO: move this to new pallet 
		#[pallet::weight(0)]
		pub fn submit_reencryption_keys(
			origin: OriginFor<T>,
			consumer: T::AccountId,
			ephemeral_public_key: Vec<u8>,
			data_public_key: Vec<u8>,
			kfrag_assignments: Vec<(T::AccountId, EncryptedFragment)>,
			secret_key_fragment: EncryptedFragment,
		) -> DispatchResult {
			// ensure_none(origin)?;
			let mut frag_holders = Vec::new();
            for assignment in kfrag_assignments.iter() {
				T::QueueProvider::submit_fragment(
					consumer.clone(),
                    data_public_key.clone(),
                    assignment.0.clone(), 
                    assignment.1.clone(),
				);
                frag_holders.push(assignment.0.clone());
            }
			T::QueueProvider::submit_ephemeral_key(consumer.clone(), ephemeral_public_key.clone(), data_public_key.clone());
			T::QueueProvider::submit_fragment_holders(consumer.clone(), data_public_key.clone(), frag_holders);
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

		let body = sp_std::str::from_utf8(&id_res).map_err(|_| Error::<T>::ResponseParsingFailure)?;
		let json = ipfs::parse(body).map_err(|_| Error::<T>::ResponseParsingFailure)?;
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
				match stat_response["StorageMax"].clone().as_u64() {
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

	// A proxy processes requests to generate kfrags
	// verify kfrag and convert to cfrag
	// encrypt cfrag for recipient
	// 
	// this would actually be better in its own pallet... not IPFS related at all
	//
	fn proxy_process_kfrag_generation_requests(account: T::AccountId) -> Result<(), Error<T>> {
		let capsule_recovery_requests = T::QueueProvider::get_capsule_recovery_requests(account.clone());

		let secret_storage = StorageValueRef::persistent(b"iris::secret");
		if let Ok(Some(local_sk)) = secret_storage.get::<[u8;32]>() {
			// key I need for decrypting SK_A
			let local_secret_key: BoxSecretKey = BoxSecretKey::from(local_sk);
			// each cap recovery request is an account id and a public key
			for cap_recovery_request in capsule_recovery_requests {
				// 1. recover secret key needed to generate kfrags
				// the text I want to decrypt (secret key generated by data owner for the proxy)
				let encrypted_sk = T::QueueProvider::get_proxy_code(
					account.clone(), cap_recovery_request.public_key.clone(),
				).unwrap();

				// convert pk vec to BoxPublicKey
				let pk_clone = encrypted_sk.public_key.clone();
				let encrypted_sk_pk_slice = iris_primitives::slice_to_array_32(&pk_clone).unwrap();
				let encrypted_sk_pub_key = BoxPublicKey::from(encrypted_sk_pk_slice.clone());
				// decrypt appropriate secret key
				let sk_plaintext = iris_primitives::decrypt_x25519(
					encrypted_sk_pub_key.clone(),
					local_secret_key.clone(),
					encrypted_sk.ciphertext,
					encrypted_sk.nonce,
				);
				// convert to SecretKey (umbral)
				let secret_key = SecretKey::from_bytes(sk_plaintext).unwrap();
				// generate new key pair 
				let mut rng = ChaCha20Rng::seed_from_u64(211u64);
				// TODO: should this happen here?
				let signer = umbral_pre::Signer::new(secret_key.clone());
				let ephemeral_sk = SecretKey::random_with_rng(rng.clone());
				let ephemeral_pk = ephemeral_sk.public_key();
				// generate kfrags
				// TODO: store/pass threshold + shares values
				let kfrags = generate_kfrags_with_rng(
				    &mut rng.clone(), &secret_key.clone(), &ephemeral_pk, &signer, 5, 3, true, true
				);
				// get recipient's x25519 public key
				let consumer_pk_bytes = pallet_authorities::Pallet::<T>::x25519_public_keys(cap_recovery_request.caller.clone());
				match Self::choose_kfrag_holders(kfrags.to_vec()) {
					Ok(kfrag_assignments) => {
						// encrypt secret of new ephemeral umbral keypair
						// consumer will require this in order to recover plaintext
						match iris_primitives::slice_to_array_32(&consumer_pk_bytes) {
							Some(pk_slice) => {
								let pk = BoxPublicKey::from(*pk_slice);
								let encrypted_ephem_sk_artifacts = iris_primitives::encrypt_x25519(
									pk, ephemeral_sk.to_string().as_bytes().to_vec(),
								);

								let call = Call::submit_reencryption_keys {
									consumer: cap_recovery_request.caller.clone(),
									// TODO: need to store the ephemeral pk somewhere, will be needed to generate cfrags
									ephemeral_public_key: ephemeral_pk.clone().to_array().to_vec(),
									data_public_key: cap_recovery_request.public_key.clone(),
									kfrag_assignments: kfrag_assignments,
									secret_key_fragment: encrypted_ephem_sk_artifacts,
								};
					
								SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
									.map_err(|()| "Unable to submit unsigned transaction.");
						
								// Some(Bytes::from(result.3.to_vec()))
							}, 
							None => {
								// do nothing?
							}
						};
					},
					Err(e) => {
						// TODO: Define some error response?
						// Some(Bytes::from("".as_bytes().to_vec()))
					}
				}
			}	
		}
		Ok(())
	}

	// kfrag holders execute this logic to reencrypt for a caller
	pub fn kfrag_holder_process_reencryption_requests(account: T::AccountId) -> Result<(), Error<T>> {
		let reencryption_requests = T::QueueProvider::get_reencryption_requests(account.clone());
		let secret_storage = StorageValueRef::persistent(b"iris::secret");
		// only proceed if we have the secret key
		if let Ok(Some(local_sk)) = secret_storage.get::<[u8;32]>() {
			let local_secret_key: BoxSecretKey = BoxSecretKey::from(local_sk);

			// each request contains (caller (consumer), data_public_key, caller_public_key)
			// use data_public_key to identify kfrag and capsule
			// use caller_public_key to encrypt capsule
			for request in reencryption_requests.iter() {
				// decrypt and recover kfrag
				let encrypted_frag = T::QueueProvider::get_kfrags(
					request.data_public_key.clone(), 
					request.caller.clone(),
					account.clone(),
				).unwrap();
				// recover original kfrag
				// the kfrag was encrypted with the proxy node's sk, so
				// we need to recover the proxy node public key

				// we stored the proxy node public key in the encrypted frag? YES
				// we need to use the pk from the encrypted frag, as we are doing already! everything is good I think
				
				// // convert to PublicKey
				let pubkey_slice_32 = iris_primitives::slice_to_array_32(encrypted_frag.public_key.as_slice()).unwrap();
				let kfrag_enc_public_key = BoxPublicKey::from(*pubkey_slice_32);
				// // decrypt the kfrag
				let kfrag_bytes = iris_primitives::decrypt_x25519(
					kfrag_enc_public_key, local_secret_key.clone(), encrypted_frag.ciphertext, encrypted_frag.nonce
				);
				let kfrag = KeyFrag::from_bytes(kfrag_bytes).unwrap();

				// recover appropriate capsule
				let capsule_data = T::QueueProvider::get_capsule(request.data_public_key.clone()).unwrap();
				let capsule = Capsule::from_bytes(&capsule_data).unwrap();
				// // 1. verify kfrag
				let mut rng = ChaCha20Rng::seed_from_u64(51u64);
				// generate keys
				let sk = SecretKey::random_with_rng(rng.clone());
				let signer = umbral_pre::Signer::new(sk.clone());
				let verifying_pk = signer.verifying_key();

				let data_pubkey_clone = request.data_public_key.clone();
				let data_pubkey_slice_32 = iris_primitives::slice_to_array_32(&data_pubkey_clone).unwrap();
				let data_public_key = PublicKey::from_bytes(data_pubkey_slice_32).unwrap();

				let consumer_ephemeral_pk_vec = T::QueueProvider::get_ephemeral_key(request.caller.clone(), request.data_public_key.clone());
				let consumer_pubkey_slice_32 = iris_primitives::slice_to_array_32(consumer_ephemeral_pk_vec.as_slice()).unwrap();
				let consumer_public_key = PublicKey::from_bytes(*consumer_pubkey_slice_32).unwrap();

				let verified_kfrag = kfrag.verify(&verifying_pk, Some(&data_public_key), Some(&consumer_public_key)).unwrap();

				let mut rng = ChaCha20Rng::seed_from_u64(31u64);
				// generate a capsule fragment
				let verified_cfrag = reencrypt_with_rng(&mut rng, &capsule, verified_kfrag);
				let cfrag_bytes = verified_cfrag.to_array().as_slice().to_vec();

				let caller_pk_vec = pallet_authorities::Pallet::<T>::x25519_public_keys(request.caller.clone());
            	let caller_pk_slice = iris_primitives::slice_to_array_32(&caller_pk_vec).unwrap();
				let caller_pk = BoxPublicKey::from(*caller_pk_slice);
				let encrypted_cfrag_data = iris_primitives::encrypt_x25519(
					caller_pk, cfrag_bytes,
				);
				// send signed tx to encode this on chain (potentially acting in capacity of proxy (substrate version))
				let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
				if !signer.can_sign() {
					log::error!(
						"No local accounts available. Consider adding one via `author_insertKey` RPC.",
					);
				}
				let results = signer.send_signed_transaction(|_acct| { 
					Call::submit_capsule_fragment {
						data_consumer: request.caller.clone(),
						public_key: request.data_public_key.clone(),
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
		// 	// key I need for decryption
		
		// 	for cap_recovery_request in capsule_recovery_requests {

		

		// let capsule_recovery_requests = T::QueueProvider::get_capsule_recovery_requests(account.clone());

		// let secret_storage = StorageValueRef::persistent(b"iris::secret");
		// if let Ok(Some(local_sk)) = secret_storage.get::<[u8;32]>() {
		// 	// key I need for decryption
		// 	let secret_key: BoxSecretKey = BoxSecretKey::from(local_sk);
		// 	for cap_recovery_request in capsule_recovery_requests {
		// 		// the text I want to decrypt
		// 		let sk_ciphertext = T::QueueProvider::proxy_code().unwrap();
		// 		// decrypt appropriate secret key
		// 		let sk_plaintext = iris_primitives::decrypt_x25519(
		// 			cap_recovery_request.ciphertext_encryption_pk.clone(),
		// 			secret_key,
		// 			sk_ciphertext,
		// 		).unwrap();
		// 		// convert to SecretKey (umbral)
		// 		let secret_key = SecretKey::from(sk_plaintext);
		// 		// generate kfrags
		// 		let kfrags = generate_kfrags_with_rng(
		// 		    &mut rng.clone(), &secret_key, &cap_recovery_request.capsule_encryption_pk, &signer, threshold, shares, true, true
		// 		);

		// 		match Self::choose_kfrag_holders(kfrags) {
		// 			Ok(kfrag_assignments) => {
		// 				let call = Call::submit_reencryption_keys { 
		// 					owner: acct_id,
		// 					public_key: pk.clone(),
		// 					kfrag_assignments: kfrag_assignments,
		// 				};
			
		// 				SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
		// 					.map_err(|()| "Unable to submit unsigned transaction.");
				
		// 				Some(Bytes::from(result.3.to_vec()))
		// 			},
		// 			Err(e) => {
		// 				// TODO: Define some error response?
		// 				Some(Bytes::from("".as_bytes().to_vec()))
		// 			}
		// 		}
				// choose kfrag holders

				// encrypt kfrags and encode
				// the same logic as the initial version of the encryption function

				// let pk = cap_recovery_request.ciphertext_encryption_pk;

				// // for each public key, find the corresponding kfrag assigned to you
				// let encrypted_kfrag_data = T::QueueProvider::get_kfrags(pk.clone(), account.clone()).unwrap();

				// // convert to PublicKey
				// let pubkey_slice_32 = iris_primitives::slice_to_array_32(encrypted_kfrag_data.public_key.as_slice()).unwrap();
				// let public_key = BoxPublicKey::from(*pubkey_slice_32);
				// // decrypt the kfrag
				// let kfrag = Self::recover_encrypted_kfrag(
				// 	public_key, secret_key.clone(), encrypted_kfrag_data.ciphertext, encrypted_kfrag_data.nonce
				// );

				// // verify kfrag
				// let mut rng = ChaCha20Rng::seed_from_u64(31u64);
				// let sk = SecretKey::random_with_rng(rng.clone());
				// let signer = umbral_pre::Signer::new(sk.clone());
				// let verifying_pk = signer.verifying_key();
				
				// // now that we have they keyfrag, we can proceed to recover capsule frag
				// // TODO: unsafe?
				// let pk_umbral = PublicKey::from_bytes(&pk).unwrap();
				// let secret_data = T::QueueProvider::get_capsule(pk.clone()).unwrap();
				// let capsule = Capsule::from_bytes(&secret_data).unwrap();
				// // 1. verify kfrag
				// let verified_kfrag = kfrag.verify(&verifying_pk, Some(&pk_umbral), Some(&sk.public_key())).unwrap();
				// // reencrypt
				// let verified_cfrag = reencrypt_with_rng(&mut rng, &capsule, verified_kfrag);
				// let cfrag_bytes = verified_cfrag.to_array().as_slice().to_vec();

				// let consumer_ephemeral_pubkey_slice_32 = iris_primitives::slice_to_array_32(cap_recovery_request.capsule_encryption_pk.as_slice()).unwrap();
				// let ephemeral_public_key = BoxPublicKey::from(*consumer_ephemeral_pubkey_slice_32);
				// // fetch crypto_box pubkey of recipient (data consumer)
				// let encrypted_cfrag_data = iris_primitives::encrypt_crypto_box(
				// 	ephemeral_public_key,
				// 	secret_key.clone(),
				// 	cfrag_bytes,
				// );
				
				// let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
				// if !signer.can_sign() {
				// 	log::error!(
				// 		"No local accounts available. Consider adding one via `author_insertKey` RPC.",
				// 	);
				// }
				// let results = signer.send_signed_transaction(|_acct| { 
				// 	Call::submit_recovered_capsule_fragment {
				// 		data_consumer: cap_recovery_request.caller.clone(),
				// 		asset_id: cap_recovery_request.asset_id,
				// 		encrypted_cfrag_data: encrypted_cfrag_data.clone(),
				// 	}
				// });
			
				// for (_, res) in &results {
				// 	match res {
				// 		Ok(()) => log::info!("Submitted results successfully"),
				// 		Err(e) => log::error!("Failed to submit transaction: {:?}",  e),
				// 	}
				// }
		Ok(())
	}

	    ///
    /// Assign each verified key fragment to a specific validator account
    /// `key_fragments`: A Vec of VerifiedKeyFrag to assign to validators
    ///
    pub fn choose_kfrag_holders(key_fragments: Vec<VerifiedKeyFrag>) -> Result<Vec<(T::AccountId, EncryptedFragment)>, Error<T>> {
        let mut assignments = Vec::new();
        let rng = ChaCha20Rng::seed_from_u64(17u64);
        let required_authorities_count = key_fragments.len() - 1;
        let authorities: Vec<T::AccountId> = pallet_authorities::Pallet::<T>::validators();
        ensure!(authorities.len() >= required_authorities_count, Error::<T>::InsufficientAuthorities);
        for i in vec![0, required_authorities_count] {
            let authority = authorities[i].clone();
            let pk_bytes: Vec<u8> = pallet_authorities::Pallet::<T>::x25519_public_keys(authority.clone());
            match iris_primitives::slice_to_array_32(&pk_bytes) {
                Some(pk_slice) => {
                    let pk = BoxPublicKey::from(*pk_slice);
                    let key_fragment = key_fragments[i].clone().unverify().to_array().as_slice().to_vec();
                    let encrypted_kfrag_data = iris_primitives::encrypt_x25519(
                        pk.clone(), key_fragment,
                    );
                    assignments.push((authority.clone(), encrypted_kfrag_data.clone()));
                },
                None => {
                    // idk yet
                }
            }
        }
        Ok(assignments)
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
		// convert to KeyFragment (TODO: safe?)
		KeyFrag::from_bytes(plaintext).unwrap()
	}
}
