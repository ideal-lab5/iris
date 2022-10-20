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
use pallet_data_assets::{MetadataProvider, QueueManager};

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
		/// get metadata of data assets
		type MetadataProvider: pallet_data_assets::MetadataProvider<Self::AssetId>;
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

	// TODO get rid of this/merge with other maps
	#[pallet::storage]
	pub type SecretKeys<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId, // the consumer
		Blake2_128Concat,
		Vec<u8>,    // the data pk
		EncryptedFragment,    // the encrypted secret key info
		OptionQuery,
	>;

	#[pallet::storage]
	pub type ReencryptionRequests<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		T::AccountId, // the fragment holder
		Vec<ReencryptionRequest<T::AccountId>>,
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
			// if let Call::name{ .. } = call {
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
			// should there be any verification that this public key was generated via the encryption? probably
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
			consumer: T::AccountId, // should this be lookup instead?
			ephemeral_public_key: Vec<u8>,
			data_public_key: Vec<u8>,
			kfrag_assignments: Vec<(T::AccountId, EncryptedFragment)>,
			encrypted_sk_box: EncryptedFragment, // recall: this key is encrypted with consumer's pk
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
				// just immediately add a reencryption request as well
				// not sure if this is going to be the long term behavior however
				ReencryptionRequests::<T>::mutate(
					assignment.0.clone(), |mut requests| {
						requests.push(ReencryptionRequest {
							caller: consumer.clone(),
							data_public_key: data_public_key.clone(),
							// caller_public_key: ephem
						});
					}
				);

                frag_holders.push(assignment.0.clone());
            }
			EphemeralKeys::<T>::insert(consumer.clone(), data_public_key.clone(), ephemeral_public_key.clone());
			FragmentOwnerSet::<T>::insert(consumer.clone(), data_public_key.clone(), frag_holders);
			SecretKeys::<T>::insert(consumer.clone(), data_public_key.clone(), encrypted_sk_box.clone());
			// TODO: emit event
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

	pub fn decrypt(
		signature: Bytes,
        signer: Bytes,
        message: Bytes,
		ciphertext: Bytes,
		asset_id: u32,
		secret_key: Bytes, // uhm... yeah that's gonna be totally fine... for now...
	) -> Option<Bytes> {
		
        let acct_bytes: [u8;32] = signer.to_vec().try_into().unwrap();
        let acct_pubkey = Public::from_raw(acct_bytes);
        let sig: Signature = Signature::from_slice(signature.to_vec().as_ref()).unwrap();
        let msg: Vec<u8> = message.to_vec();
        let acct_id: T::AccountId = T::AccountId::decode(&mut &acct_bytes[..]).unwrap();

        if sig.verify(msg.as_slice(), &acct_pubkey) {
			let sk_vec = secret_key.to_vec();
			let sk_slice = iris_primitives::slice_to_array_32(&sk_vec).unwrap();
			let sk = BoxSecretKey::from(*sk_slice);
			// map asset_id to public_key 
            let asset_id_as_type = TryInto::<T::AssetId>::try_into(asset_id).ok().unwrap();
			// again shouldn't make this assumption... will fix later when testing
			let metadata = T::MetadataProvider::get(asset_id_as_type.clone()).unwrap();

			let capsule_vec = Capsules::<T>::get(metadata.public_key.clone()).unwrap();
			let capsule: Capsule = Capsule::from_bytes(capsule_vec).unwrap();
			let encrypted_sk = SecretKeys::<T>::get(acct_id.clone(), metadata.public_key.clone()).unwrap();

			// decrypt secret key
			return Some(Self::do_decrypt(
				acct_id.clone(), 
				ciphertext.to_vec(),
				metadata.public_key.clone(),
				encrypted_sk,
				sk,
				capsule,
			));

		}

		Some(Bytes::from(Vec::new()))
	}

	fn do_decrypt(
		account_id: T::AccountId,
		ciphertext: Vec<u8>,
		data_public_key_vec: Vec<u8>,
		encrypted_decryption_key: EncryptedFragment,
		x25519_sk: BoxSecretKey,
		capsule: Capsule,
	) -> Bytes {
		let encrypted_capsule_fragments = VerifiedCapsuleFrags::<T>::get(
			account_id.clone(), data_public_key_vec.clone(),
		);

		let verified_capsule_fragments = iris_primitives::convert_encrypted_capsules(
			encrypted_capsule_fragments, x25519_sk.clone(),
		);

		// the public key associated with secret that encrypted the cfrags
		let pk_for_encrypted_sk = encrypted_decryption_key.public_key.clone();
		let pk_slice = iris_primitives::slice_to_array_32(&pk_for_encrypted_sk).unwrap();
		let pk = BoxPublicKey::from(*pk_slice);

		let decrypted_tpre_sk_bytes = iris_primitives::decrypt_x25519(
			pk.clone(),
			x25519_sk.clone(),
			encrypted_decryption_key.ciphertext.clone(),
			encrypted_decryption_key.nonce.clone(),
		);
		let decrypted_sk = SecretKey::from_bytes(decrypted_tpre_sk_bytes).unwrap();

		let pk_for_data = data_public_key_vec.clone();
		let data_pk_slice = iris_primitives::slice_to_array_32(&pk_for_data).unwrap();
		let data_public_key = PublicKey::from_bytes(&data_pk_slice).unwrap();

		let plaintext = match umbral_pre::decrypt_reencrypted(
			&decrypted_sk, &data_public_key, &capsule,
			verified_capsule_fragments, &ciphertext,
		) {
			Ok(plaintext) => plaintext.to_vec(),
			Err(e) => {
				"".as_bytes().to_vec()
			}
		};
		Bytes::from(plaintext)
	}

    /// TODO: look at client\network\src\config.rs for sk generation/storage + write to file
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

		// how do I test this?
        if sig.verify(msg.as_slice(), &acct_pubkey) {
            let proxy_pk_vec = pallet_authorities::Pallet::<T>::x25519_public_keys(proxy_acct_id.clone());
            let proxy_pk_slice = iris_primitives::slice_to_array_32(&proxy_pk_vec).unwrap();
            let proxy_pk = BoxPublicKey::from(*proxy_pk_slice);
            let plaintext_as_slice: &[u8] = &plaintext.to_vec();
			Self::do_encrypt(plaintext_as_slice, shares, threshold, proxy_pk, acct_id, proxy_acct_id.clone());
        }

        None 
    }

	fn do_encrypt(
		plaintext: &[u8],
		shares: usize,
		threshold: usize,
		proxy_pk: BoxPublicKey,
		owner_account_id: T::AccountId,
		proxy_account_id: T::AccountId,
	) -> Bytes {
		let ciphertext = match iris_primitives::encrypt(plaintext, shares, threshold, proxy_pk) {
			// (capsule, ciphertext, public key, encrypted secret key)
			Ok(result) => {
				let data_capsule_vec: Vec<u8> = result.0.to_array().as_slice().to_vec();
				let pk: Vec<u8> = result.2.to_array().as_slice().to_vec();

				let call = Call::submit_encryption_artifacts { 
					owner: owner_account_id,
					data_capsule: data_capsule_vec,
					public_key: pk.clone(),
					proxy: proxy_account_id.clone(),
					sk_encryption_info: result.3.clone(),
				};
	
				SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
					.map_err(|()| "Unable to submit unsigned transaction.");
		
				result.1.to_vec()
			},
			Err(e) => {
				"".as_bytes().to_vec()
			}
		};
		Bytes::from(ciphertext)
	}

	/// A proxy processes requests to generate kfrags for an authorized caller
	/// 
	/// * `account`: The account of the proxy node to execute commands and submit results
	///
	fn proxy_process_kfrag_generation_requests(
		account: T::AccountId,
		candidates: Vec<(T::AccountId, Vec<u8>)>,
	) -> Result<(), Error<T>> {
		let capsule_recovery_requests = CapsuleRecoveryRequests::<T>::get(account.clone());
		let secret_storage = StorageValueRef::persistent(b"iris::x25519");
		if let Ok(Some(local_sk)) = secret_storage.get::<[u8;32]>() {
			// key I need for decrypting SK_A
			let local_secret_key: BoxSecretKey = BoxSecretKey::from(local_sk);
			// each cap recovery request is an account id and a public key
			for cap_recovery_request in capsule_recovery_requests {
				// 1. recover secret key needed to generate kfrags
				// TODO: handle error
				let sk_box = ProxyCodes::<T>::get(
					account.clone(), 
					cap_recovery_request.public_key.clone()
				).unwrap();

				// convert pk vec to BoxPublicKey
				let pk_clone = sk_box.public_key.clone();
				let encrypted_sk_pk_slice = iris_primitives::slice_to_array_32(&pk_clone).unwrap();
				let encrypted_sk_pub_key = BoxPublicKey::from(encrypted_sk_pk_slice.clone());
				// decrypt appropriate secret key
				let sk_plaintext = iris_primitives::decrypt_x25519(
					encrypted_sk_pub_key.clone(),
					local_secret_key.clone(),
					sk_box.ciphertext,
					sk_box.nonce,
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
				// TODO: store/pass threshold + shares values? hard coded at {5, 3} currently
				// false/false  vs true/true? 
				let kfrags = generate_kfrags_with_rng(
				    &mut rng.clone(), &secret_key.clone(), &ephemeral_pk, &signer, 5, 3, true, true
				);
				// TODO: Is this really going to work? get recipient's x25519 public key
				let consumer_pk_bytes = pallet_authorities::Pallet::<T>::x25519_public_keys(
					cap_recovery_request.caller.clone()
				);
				match Self::choose_kfrag_holders(kfrags.to_vec(), candidates.clone()) {
					Ok(kfrag_assignments) => {
						// encrypt secret of new ephemeral umbral keypair
						// consumer will require this in order to recover plaintext
						// TODO: does this really need a match statement?
						match iris_primitives::slice_to_array_32(&consumer_pk_bytes) {
							Some(pk_slice) => {
								let pk = BoxPublicKey::from(*pk_slice);
								let mut rng = ChaCha20Rng::seed_from_u64(31u64);
								let data_owner_umbral_sk = SecretKey::random_with_rng(rng.clone());
								let secret_key_bytes = data_owner_umbral_sk.to_secret_array()
									.as_secret()
									.to_vec();
								let encrypted_ephem_sk_artifacts = iris_primitives::encrypt_x25519(
									pk, secret_key_bytes,
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
										encrypted_sk_box: encrypted_ephem_sk_artifacts.clone(),
									}
								});
							}, 
							None => {
								panic!("uhoh");
								// do nothing?
							}
						};
					},
					Err(e) => {
						panic!("I need to make this an actual error response {:?}", e);
						// TODO: Define some error response?
						// Some(Bytes::from("".as_bytes().to_vec()))
					}
				}
			}	
		}
		Ok(())
	}

	/// kfrag holders execute this logic to reencrypt for a caller
	fn kfrag_holder_process_reencryption_requests(
		account: T::AccountId,
	) -> Result<(), Error<T>> {
		let reencryption_requests = ReencryptionRequests::<T>::get(account.clone());
		
		let secret_storage = StorageValueRef::persistent(b"iris::x25519");
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

				// let data_pubkey_clone = request.data_public_key.clone();
				// panic!("{:?}", data_pubkey_clone.len());
				// let data_pubkey_slice_32 = iris_primitives::slice_to_array_32(&data_pubkey_clone).unwrap();
				// let data_public_key = PublicKey::from_bytes(data_pubkey_slice_32).unwrap();
				let data_public_key = PublicKey::from_bytes(&request.data_public_key.clone()).unwrap();

				let consumer_ephemeral_pk_vec = EphemeralKeys::<T>::get(request.caller.clone(), request.data_public_key.clone());
				let consumer_public_key = PublicKey::from_bytes(&consumer_ephemeral_pk_vec).unwrap();

				// TODO
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
    /// Assign each verified key fragment to a validator account
	/// 
    /// `key_fragments`: A Vec of VerifiedKeyFrag to assign to validators
    ///
    pub fn choose_kfrag_holders(
		key_fragments: Vec<VerifiedKeyFrag>,
		candidates: Vec<(T::AccountId, Vec<u8>)>,
	) -> Result<Vec<(T::AccountId, EncryptedFragment)>, Error<T>> {
        let mut assignments = Vec::new();
        let rng = ChaCha20Rng::seed_from_u64(17u64);
        let required_authorities_count = key_fragments.len() - 1;
        // let authorities: Vec<T::AccountId> = pallet_authorities::Pallet::<T>::validators();
        ensure!(candidates.len() > required_authorities_count, Error::<T>::InsufficientAuthorities);
        for i in vec![0, required_authorities_count] {
            let candidate = candidates[i].clone();
            // let pk_bytes: Vec<u8> = pallet_authorities::Pallet::<T>::x25519_public_keys(candidate.clone());
            match iris_primitives::slice_to_array_32(&candidate.1) {
                Some(pk_slice) => {
                    let pk = BoxPublicKey::from(*pk_slice);
                    let key_fragment = key_fragments[i].clone()
						.unverify()
						.to_array()
						.as_slice()
						.to_vec();
                    let encrypted_kfrag_data = iris_primitives::encrypt_x25519(
                        pk.clone(), key_fragment,
                    );
                    assignments.push((candidate.0.clone(), encrypted_kfrag_data.clone()));
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

	// what if public_key dne?
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
	fn process_decryption_delegation(
		account: AccountId,
		candidates: Vec<(AccountId, Vec<u8>)>,
	);
	fn process_reencryption_requests(account: AccountId);
}

impl<T: Config> OffchainKeyManager<T::AccountId> for Pallet<T> {
	fn process_decryption_delegation(
		account: T::AccountId,
		candidates: Vec<(T::AccountId, Vec<u8>)>
	) {
		Self::proxy_process_kfrag_generation_requests(account, candidates);
	}

	fn process_reencryption_requests(account: T::AccountId) {
		Self::kfrag_holder_process_reencryption_requests(account);
	}
}
