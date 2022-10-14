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

//! # Proxy Pallet
//!
//! @author driemworks
//! 
//! ## Description 
//! 
//! 

#![cfg_attr(not(feature = "std"), no_std)]

mod mock;
mod tests;

use frame_support::{
	ensure, parameter_types,
	pallet_prelude::*,
	traits::{
		EstimateNextSessionRotation, Get, Currency, LockableCurrency,
		DefensiveSaturating, LockIdentifier, WithdrawReasons,
	},
	BoundedVec,
};
use scale_info::prelude::string::ToString;
use scale_info::TypeInfo;
pub use pallet::*;
use sp_runtime::{
	SaturatedConversion,
	traits::{CheckedSub, Convert, Zero, Verify},
};
use sp_staking::offence::{Offence, OffenceError, ReportOffence};
use sp_std::{
	collections::btree_map::BTreeMap,
	str,
	prelude::*
};
use sp_core::{
	Bytes,
    offchain::{
        OpaqueMultiaddr, StorageKind,
    },
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
	offchain::storage::StorageValueRef,
	traits::StaticLookup,
};
use codec::HasCompact;
use iris_primitives::*;
use pallet_authorities::EraProvider;
use pallet_data_assets::QueueManager;

use umbral_pre::*;

use rand_chacha::{
	ChaCha20Rng,
	rand_core::SeedableRng,
};

use crypto_box::{
    aead::{Aead, AeadCore, Payload},
	SalsaBox, PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, Nonce,
};

pub const LOG_TARGET: &'static str = "runtime::proxy";
// TODO: should a new KeyTypeId be defined? e.g. b"iris"
// pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");


// type BalanceOf<T> =
// 	<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;


pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub struct CapsuleRecoveryRequest<AccountId> {
    pub caller: AccountId,
    pub public_key: Vec<u8>,
}

pub mod crypto {
	use super::KEY_TYPE;
	use sp_core::crypto::KeyTypeId;
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

	/// TODO: Only using pallet_assets::config because I'm lazy
	#[pallet::config]
	pub trait Config: CreateSignedTransaction<Call<Self>> + frame_system::Config +
															pallet_assets::Config +
					  									 	pallet_authorities::Config
	{
		/// The Event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		/// the overarching call type
		type Call: From<Call<Self>>;
		/// the authority id used for sending signed txs
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
		/// read/write to data ingestion/ejection queues
		type QueueManager: pallet_data_assets::QueueManager<Self::AccountId, Self::Balance>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	// storage
	    // TODO: Explore making types for TPREPublicKey, Ciphertext
    // maps pubkey to ciphertext/capsule
    #[pallet::storage]
    pub type Capsules<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Vec<u8>,  // public key
        Vec<u8>, // capsule data 
        OptionQuery,
    >;

    #[pallet::storage]
    pub type Proxy<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Vec<u8>,  // public key
        T::AccountId, // proxy accountid
        OptionQuery,
    >;

    #[pallet::storage]
    pub type FragmentOwnerSet<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId, // consumer acct id
        Blake2_128Concat,
        Vec<u8>, // public key (umbral)
        Vec<T::AccountId>,
        ValueQuery,
    >;

    #[pallet::storage]
    pub type Fragments<T: Config> = StorageNMap<
        _,
        (
            NMapKey<Blake2_128Concat, T::AccountId>, // originator/consumer/decryptor/delegatee
            NMapKey<Blake2_128Concat, Vec<u8>>,      // public key
            NMapKey<Blake2_128Concat, T::AccountId>  // frag holder
        ),
        EncryptedFragment, // the information needed to decrypt encrypted fragment knowing secret key
        OptionQuery,
    >;

    /// maps a key fragment holder to a vec of public keys for which
    /// they have been tasked with recovering the capsule fragmentr
    #[pallet::storage]
    pub type CapsuleRecoveryRequests<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId, // proxy address
        Vec<CapsuleRecoveryRequest<T::AccountId>>, // public key associated with umbral encrypted data
        ValueQuery,
    >;

    #[pallet::storage]
    pub type VerifiedCapsuleFrags<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        Vec<u8>,
        Vec<EncryptedFragment>, // <-- TODO: should rename this struct to something more generic
        ValueQuery,
    >;

    // could potentially exist elsewhere
    // lots of these storage maps could probably be simplified, need to do more analysis
    #[pallet::storage]
    pub type ProxyCodes<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId, // proxy acct id
        Blake2_128Concat,
        Vec<u8>, // the public key
        EncryptedFragment, // the info needed to decrypt the secret key
        OptionQuery,
    >;

    #[pallet::storage]
    pub type EphemeralKeys<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId, // the consumer
        Blake2_128Concat,
        Vec<u8>,    // the data pk
        Vec<u8>,    // the ephemeral pk for the data/consumer combi
        ValueQuery,
    >;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {

	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		InsufficientAuthorities,
	}

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		/// Validate unsigned call to this module.
		///
		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
			// TODO
			// if let Call::submit_reencryption_keys{ .. } = call {
				Self::validate_transaction_parameters()
			// } else {
			// 	InvalidTransaction::Call.into()
			// }
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {

		#[pallet::weight(0)]
		pub fn submit_capsule_fragment(
			origin: OriginFor<T>,
			data_consumer: T::AccountId,
			public_key: Vec<u8>,
			encrypted_cfrag_data: iris_primitives::EncryptedFragment,
		) -> DispatchResult {
			VerifiedCapsuleFrags::<T>::mutate(data_consumer, public_key, |cfrags| {
            	cfrags.push(encrypted_cfrag_data);
        	});
			// deposit event
			Ok(())
		}
		
		/// called by a proxy who generated new kfrags for another node
		#[pallet::weight(0)]
		pub fn submit_reencryption_keys(
			origin: OriginFor<T>,
			consumer: T::AccountId,
			ephemeral_public_key: Vec<u8>,
			data_public_key: Vec<u8>,
			kfrag_assignments: Vec<(T::AccountId, EncryptedFragment)>,
			secret_key_fragment: EncryptedFragment,
		) -> DispatchResult {
			// ensure_signed(origin)?;
			let mut frag_holders = Vec::new();
			// this is a lot of db writes... how can we minimize this?
            for assignment in kfrag_assignments.iter() {
				Fragments::<T>::insert(
					(
						consumer.clone(),
						data_public_key.clone(),
						assignment.0.clone(),
					), 
					assignment.1.clone(),
				);
                frag_holders.push(assignment.0.clone());
            }
			EphemeralKeys::<T>::insert(consumer.clone(), data_public_key.clone(), ephemeral_public_key.clone());
			FragmentOwnerSet::<T>::insert(consumer.clone(), data_public_key.clone(), frag_holders);
			// TODO: emite event
			Ok(())
		}

		#[pallet::weight(0)]
        pub fn submit_encryption_artifacts(
            origin: OriginFor<T>,
            owner: T::AccountId,
            data_capsule: Vec<u8>,
            public_key: Vec<u8>,
            proxy: T::AccountId,
            sk_encryption_info: EncryptedFragment,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Capsules::<T>::insert(public_key.clone(), data_capsule);
            Proxy::<T>::insert(public_key.clone(), proxy.clone());
            // need to store the sk_encryption_info
            ProxyCodes::<T>::insert(proxy.clone(), public_key.clone(), sk_encryption_info.clone());
			T::QueueManager::add_ingestion_staging(owner.clone(), public_key.clone());
            // TODO: emit event
            Ok(())
        }

	}
}

impl<T: Config> Pallet<T> {

    /// TODO: should it be signed or unsigned tx? probably signed right?
    /// checkout: client\network\src\config.rs for sk generation/storage + write to file
    /// Recover signing acct and use it to encrypt the data and submit unsigned tx
    pub fn encrypt(
        plaintext: Bytes,
        signature: Bytes,
        signer: Bytes,
        message: Bytes,
        shares: usize,
        threshold: usize,
        proxy: Bytes,
    ) -> Option<Bytes> {

        let proxy_acct_bytes: [u8;32] = proxy.to_vec().try_into().unwrap();
        let proxy_acct_id: T::AccountId = T::AccountId::decode(&mut &proxy_acct_bytes[..]).unwrap();

        let acct_bytes: [u8;32] = signer.to_vec().try_into().unwrap();
        let acct_pubkey = Public::from_raw(acct_bytes);
        let sig: Signature = Signature::from_slice(signature.to_vec().as_ref()).unwrap();
        let msg: Vec<u8> = message.to_vec();

        let acct_id: T::AccountId = T::AccountId::decode(&mut &acct_bytes[..]).unwrap();

        if sig.verify(msg.as_slice(), &acct_pubkey) {
            let proxy_pk_vec = pallet_authorities::Pallet::<T>::x25519_public_keys(proxy_acct_id.clone());
            let proxy_pk_slice = iris_primitives::slice_to_array_32(&proxy_pk_vec).unwrap();
            let proxy_pk = BoxPublicKey::from(*proxy_pk_slice);
            let plaintext_as_slice: &[u8] = &plaintext.to_vec();

            match iris_primitives::encrypt_phase_1(plaintext_as_slice, shares, threshold, proxy_pk) {
                // capsule, ciphertext, public key, encrypted secret key
                Ok(result) => {
                    let data_capsule_vec: Vec<u8> = result.0.to_array().as_slice().to_vec();
                    let pk: Vec<u8> = result.2.to_array().as_slice().to_vec();

                    let call = Call::submit_encryption_artifacts { 
                        owner: acct_id,
                        data_capsule: data_capsule_vec,
                        public_key: pk.clone(),
                        proxy: proxy_acct_id.clone(),
                        sk_encryption_info: result.3.clone(),
                    };
        
                    SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
                        .map_err(|()| "Unable to submit unsigned transaction.");
            
                    Some(Bytes::from(result.1.to_vec()))
                },
                Err(e) => {
                    Some(Bytes::from("".as_bytes().to_vec()))
                }
            };
        }

        None 
    }

	// fn do_encrypt(plaintext: &[u8], proxy: T::AccountId, shares: usize, threshold: usize) {
	// 	let proxy_pk_vec = pallet_authorities::Pallet::<T>::x25519_public_keys(proxy_acct_id.clone());
	// 	let proxy_pk_slice = iris_primitives::slice_to_array_32(&proxy_pk_vec).unwrap();
	// 	let proxy_pk = BoxPublicKey::from(*proxy_pk_slice);

	// 	match iris_primitives::encrypt_phase_1(plaintext_as_slice, shares, threshold, proxy_pk) {
	// 		// capsule, ciphertext, public key, encrypted secret key
	// 		Ok(result) => {
	// 			let data_capsule_vec: Vec<u8> = result.0.to_array().as_slice().to_vec();
	// 			let pk: Vec<u8> = result.2.to_array().as_slice().to_vec();

	// 			let call = Call::submit_encryption_artifacts { 
	// 				owner: acct_id,
	// 				data_capsule: data_capsule_vec,
	// 				public_key: pk.clone(),
	// 				proxy: proxy_acct_id.clone(),
	// 				sk_encryption_info: result.3.clone(),
	// 			};
	
	// 			SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
	// 				.map_err(|()| "Unable to submit unsigned transaction.");
		
	// 			Some(Bytes::from(result.1.to_vec()))
	// 		},
	// 		Err(e) => {
	// 			Some(Bytes::from("".as_bytes().to_vec()))
	// 		}
	// 	};
	// }

	// A proxy processes requests to generate kfrags
	// verify kfrag and convert to cfrag
	// encrypt cfrag for recipient
	// 
	// this would actually be better in its own pallet... not IPFS related at all
	//
	fn proxy_process_kfrag_generation_requests(account: T::AccountId) -> Result<(), Error<T>> {
		let capsule_recovery_requests = CapsuleRecoveryRequests::<T>::get(account.clone());

		let secret_storage = StorageValueRef::persistent(b"iris::secret");
		if let Ok(Some(local_sk)) = secret_storage.get::<[u8;32]>() {
			// key I need for decrypting SK_A
			let local_secret_key: BoxSecretKey = BoxSecretKey::from(local_sk);
			// each cap recovery request is an account id and a public key
			for cap_recovery_request in capsule_recovery_requests {
				// 1. recover secret key needed to generate kfrags
				let encrypted_sk = ProxyCodes::<T>::get(account.clone(), cap_recovery_request.public_key.clone()).unwrap();

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
					
								// send signed tx to encode this on chain (potentially acting in capacity of proxy (substrate version))
								let tx_signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
								if !tx_signer.can_sign() {
									log::error!(
										"No local accounts available. Consider adding one via `author_insertKey` RPC.",
									);
								}
								let _results = tx_signer.send_signed_transaction(|_account| {
									Call::submit_reencryption_keys {
										consumer: cap_recovery_request.caller.clone(),
										// TODO: need to store the ephemeral pk somewhere, will be needed to generate cfrags
										ephemeral_public_key: ephemeral_pk.clone().to_array().to_vec(),
										data_public_key: cap_recovery_request.public_key.clone(),
										kfrag_assignments: kfrag_assignments.clone(),
										secret_key_fragment: encrypted_ephem_sk_artifacts.clone(),
									}
								});
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
	pub fn kfrag_holder_process_reencryption_requests(
		account: T::AccountId, 
		reencryption_requests: Vec<iris_primitives::ReencryptionRequest<T::AccountId>>,
	) -> Result<(), Error<T>> {
		
		// TODO: where should reencryption requests come from? for now, just make it an arg?
		// let reencryption_requests = ReencryptionRequests::<T>::get(account.clone());
		
		let secret_storage = StorageValueRef::persistent(b"iris::secret");
		// only proceed if we have the secret key
		if let Ok(Some(local_sk)) = secret_storage.get::<[u8;32]>() {
			let local_secret_key: BoxSecretKey = BoxSecretKey::from(local_sk);

			// each request contains (caller (consumer), data_public_key, caller_public_key)
			for request in reencryption_requests.iter() {
				// decrypt and recover kfrag
				let encrypted_frag = Fragments::<T>::get((
					request.caller.clone(),
					request.data_public_key.clone(), 
					account.clone(),
				)).unwrap();
				// // convert to PublicKey
				let pubkey_slice_32 = iris_primitives::slice_to_array_32(encrypted_frag.public_key.as_slice()).unwrap();
				let kfrag_enc_public_key = BoxPublicKey::from(*pubkey_slice_32);
				// // decrypt the kfrag
				let kfrag_bytes = iris_primitives::decrypt_x25519(
					kfrag_enc_public_key, local_secret_key.clone(), encrypted_frag.ciphertext, encrypted_frag.nonce
				);
				let kfrag = KeyFrag::from_bytes(kfrag_bytes).unwrap();

				// recover appropriate capsule
				let capsule_data = Capsules::<T>::get(request.data_public_key.clone()).unwrap();
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

				let consumer_ephemeral_pk_vec = EphemeralKeys::<T>::get(request.caller.clone(), request.data_public_key.clone());
				
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
				let tx_signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
				if !tx_signer.can_sign() {
					log::error!(
						"No local accounts available. Consider adding one via `author_insertKey` RPC.",
					);
				}
				let results = tx_signer.send_signed_transaction(|_acct| { 
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

	fn validate_transaction_parameters() -> TransactionValidity {
		ValidTransaction::with_tag_prefix("iris")
			.longevity(5)
			.propagate(true)
			.build()
	}

	pub fn add_capsule_recovery_request(
        account: T::AccountId,
        public_key: Vec<u8>, 
    ) {
        // NOTE: this assumes there's at least one proxy available.
        // TODO: revisit this when testing
        let proxy = Proxy::<T>::get(public_key.clone()).unwrap();
        // get proxy node accountid
		// Q: should these requests live here or another pallet?
        CapsuleRecoveryRequests::<T>::mutate(proxy, |mut pks| {
            pks.push(CapsuleRecoveryRequest {
                caller: account,
                public_key: public_key.clone(),
            });
        });
    }
}

pub trait Proxies<AccountId> {
	fn proxy_for(public_key: Vec<u8>) -> Option<AccountId>;
}

impl<T: Config> Proxies<T::AccountId> for Pallet<T> {
	fn proxy_for(public_key: Vec<u8>) -> Option<T::AccountId> {
		Proxy::<T>::get(public_key)
	}
}

pub trait OffchainKeyManager<AccountId> {
	// should return Result<> instead
	fn process_decryption_delegation(account: AccountId);
	fn process_reencryption_requests(
		account: AccountId, 
		reencryption_requests: Vec<iris_primitives::ReencryptionRequest<AccountId>>,
	);
}

impl<T: Config> OffchainKeyManager<T::AccountId> for Pallet<T> {
	fn process_decryption_delegation(account: T::AccountId) {
		Self::proxy_process_kfrag_generation_requests(account);
	}

	fn process_reencryption_requests(
		account: T::AccountId, 
		reencryption_requests: Vec<iris_primitives::ReencryptionRequest<T::AccountId>>,
	) {
		Self::kfrag_holder_process_reencryption_requests(account, reencryption_requests);
	}
}