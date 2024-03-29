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
	ensure,
	pallet_prelude::*,
	traits::Randomness,
};
// use scale_info::prelude::string::ToString;
use scale_info::TypeInfo;
pub use pallet::*;
use sp_runtime::{
	traits::{TrailingZeroInput, Verify},
};
use sp_std::{
	str,
	prelude::*
};
use sp_core::{
	Bytes,
	crypto::KeyTypeId,
	sr25519::{Signature, Public},
};
use frame_system::{
	ensure_signed,
	offchain::{
		SubmitTransaction, Signer, SendSignedTransaction,
	}
};
use sp_runtime::offchain::storage::StorageValueRef;
use iris_primitives::*;
use pallet_data_assets::{MetadataProvider, QueueManager};

use umbral_pre::*;

use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

// use rand_core::{CryptoRng, RngCore};

use crypto_box::{
	PublicKey as BoxPublicKey, SecretKey as BoxSecretKey,
};

pub const LOG_TARGET: &str = "runtime::proxy";
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub struct TPREEncryptionArtifact<AccountId> {
	pub capsule: Vec<u8>,
	pub proxy: AccountId,
}

#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub struct ReencryptionArtifact<AccountId> {
	pub verifying_key: Vec<u8>,
	pub secret: EncryptedBox,
	/// The sr25519 public key created by a proxy node and intended for a 
	/// specific authorized data consumer
	pub ephemeral_public_key: Vec<u8>,
	// can this be a hashmap isntead of Vec? BTreeMap?
	// are there performance implications? this will never be very large
	pub verified_kfrags: Vec<(AccountId, EncryptedBox)>,
}

#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub struct KeyFragGenerationRequest<AccountId> {
    pub caller: AccountId,
    pub data_public_key: Vec<u8>,
	pub consumer_public_key: Vec<u8>,
}

#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub struct CapsuleFragmentGenerationRequest<AccountId> {
    pub caller: AccountId,
    pub data_public_key: Vec<u8>,
    pub caller_public_key: Vec<u8>,
}

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
		type MetadataProvider: pallet_data_assets::MetadataProvider<u32>;
		/// Something that provides randomness in the runtime.
		type Randomness: Randomness<Self::Hash, Self::BlockNumber>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

    #[pallet::storage]
    pub type EncryptionArtifacts<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Vec<u8>,  // public key -> should use a type alias instead...
        TPREEncryptionArtifact<T::AccountId>,
        OptionQuery,
    >;

	#[pallet::storage]
	pub type ReencryptionArtifacts<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId, // "consumer"
		Blake2_128Concat,
		Vec<u8>, // "public key"
		ReencryptionArtifact<T::AccountId>,
		OptionQuery,
	>;

    /// maps a key fragment holder to a vec of public keys for which
    /// they have been tasked with recovering the capsule fragmentr
    #[pallet::storage]
    pub type KeyFragGenerationRequests<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId, // proxy address
        Vec<KeyFragGenerationRequest<T::AccountId>>, // public key associated with umbral encrypted data
        ValueQuery,
    >;

    #[pallet::storage]
    pub type EncryptedCapsuleFrags<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        Vec<u8>,
        Vec<EncryptedBox>, // <-- TODO: should rename this struct to something more generic
        ValueQuery,
    >;

	#[pallet::storage]
	pub type CapsuleFragmentGenerationRequests<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		T::AccountId, // the fragment holder
		Vec<CapsuleFragmentGenerationRequest<T::AccountId>>,
		ValueQuery,
	>;

	#[pallet::storage]
	pub type ProxyCodes<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId, // proxy acct id
		Blake2_128Concat,
		Vec<u8>, // the public key
		EncryptedBox, // the info needed to decrypt the secret key
		OptionQuery,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		EncryptionArtifactsSubmitted,
		ReencryptionComplete,
		ReencapsulationComplete,
	}

	#[pallet::error]
	pub enum Error<T> {
		InsufficientAuthorities,
		InvalidPublicKeyLength,
		InsufficientCapsuleFrags,
	}

	#[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		/// Validate unsigned call to this module.
		fn validate_unsigned(_source: TransactionSource, _call: &Self::Call) -> TransactionValidity {
			// TODO: accept all for now
			// if let Call::name{ .. } = call {
				Self::validate_transaction_parameters()
			// } else {
			// 	InvalidTransaction::Call.into()
			// }
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {

		/// This function allows validators to submit encrypted capsule fragments to be encoded in the runtime. 
		/// In general, this functional should be called *only* by offchain workers, which is why the weight is left
		/// as 0.
		/// 
		/// `data_consumer`: The account id for which the capsule fragment has been created
		/// `public_key`: The unique public key that identifies the encrypted data
		/// `encrypted_cfrag_data`: The encrypted capsule fragment
		/// 
		#[pallet::weight(0)]
		pub fn submit_capsule_fragment(
			origin: OriginFor<T>,
			data_consumer: T::AccountId,
			public_key: Vec<u8>,
			encrypted_cfrag_data: EncryptedBox,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			// should there be any verification that this public key was generated via the encryption? probably
			EncryptedCapsuleFrags::<T>::mutate(data_consumer, public_key.clone(), |cfrags| {
            	cfrags.push(encrypted_cfrag_data);
        	});
			// cleanup
			CapsuleFragmentGenerationRequests::<T>::mutate(who, |reqs| {
				reqs.retain(|r| *r.data_public_key != public_key.clone());
			});
			Self::deposit_event(Event::ReencapsulationComplete);
			Ok(())
		}
		
		/// Thus function is intended to be called by a proxy node who generated key fragments.
		/// 
		/// `consumer`: The account for which key fragments were generated
		/// `receiving_public_key`: A new key created by the proxy and whose secret is provided to the consumer.
		/// `delegating_public_key`: The public key of the delegating account (this will be the same unique pubkey 
		/// 							generated when we encrypted the data).
		///  `consumer_public_key`: The public key provided by the consumer
		/// `verifying_public_key`: The public key for the verifying keypair (generated during reencryptiog)
		/// `kfrag_assignments`: A map which assigns encrypted key fragments to specific validator nodes
		/// `encrypted_receiving_sk`: A secret key that should be encrytped with the consumer_public_key
		/// 
		#[pallet::weight(0)]
		pub fn submit_reencryption_keys(
			origin: OriginFor<T>,
			consumer: T::AccountId,
			receiving_public_key: Vec<u8>,
			delegating_public_key: Vec<u8>,
			consumer_public_key: Vec<u8>, // maybe not needed
			verifying_public_key: Vec<u8>,
			kfrag_assignments: Vec<(T::AccountId, EncryptedBox)>,
			encrypted_receiving_sk: EncryptedBox,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			// this probably won't stay like this forever but it's fine for now I guess, makes testing easier
            for assignment in kfrag_assignments.iter() {
				CapsuleFragmentGenerationRequests::<T>::mutate(
					assignment.0.clone(), |requests| {
						requests.push(CapsuleFragmentGenerationRequest {
							caller: consumer.clone(),
							data_public_key: delegating_public_key.clone(),
							caller_public_key: consumer_public_key.clone(),
						});
					}
				);
            }

			ReencryptionArtifacts::<T>::insert(
				consumer, 
				delegating_public_key.clone(), 
				ReencryptionArtifact {
					verifying_key: verifying_public_key,
					secret: encrypted_receiving_sk,
					verified_kfrags: kfrag_assignments,
					ephemeral_public_key: receiving_public_key,
				}
			);
			// cleanup keyfrag requests
			KeyFragGenerationRequests::<T>::mutate(who, |reqs| {
				reqs.retain(|r| *r.data_public_key != delegating_public_key);
			});
			Self::deposit_event(Event::ReencryptionComplete);
			Ok(())
		}

		/// This function allows encryption artifacts to be encoded on chain.
		/// 
		/// * `owner`: The owner of the encrypted data
		/// * `proxy`: The proxy assigned to process reencryption requests
		/// * `capsule`: The newly created capsule object to be encoded
		/// * `public_key`: The newly created public key to be encoded
		/// * `encrypted_sk_box`: The newly created and ecnrypted secret for the owner
		/// 
		#[pallet::weight(0)]
        pub fn submit_encryption_artifacts(
            _origin: OriginFor<T>,
            owner: T::AccountId,
			proxy: T::AccountId,
            capsule: Vec<u8>,
            public_key: Vec<u8>,
            encrypted_sk_box: EncryptedBox,
        ) -> DispatchResult {
            // ensure_signed(origin)?;
			EncryptionArtifacts::<T>::insert(public_key.clone(), TPREEncryptionArtifact {
				capsule,
				proxy: proxy.clone(),
			});
            ProxyCodes::<T>::insert(proxy, public_key.clone(), encrypted_sk_box);
			T::QueueManager::add_ingestion_staging(owner, public_key);
            Self::deposit_event(Event::EncryptionArtifactsSubmitted);
            Ok(())
        }

	}
}

impl<T: Config> Pallet<T> {

	///
	/// Attempt to decrypt the ciphertext.
	/// Decryption will only be successful if the caller has sufficiently many capsule fragments.
	/// 
	/// * `signature`: The signature generated by the signer when signing the message
	/// * `signer`:  The (expected) account id of the account that signed the message
	/// * `message`: The signed message
	/// * `ciphertext`: Some ciphertext to be decrypted
	/// * `asset_id`: The unique asset id that identifies the on-chain asset associated with the data
	/// * `secret_key`: An X25519 secret key whose public key was used when authorization was granted 
	///                 and capsule fragments were created.
	/// 
	pub fn decrypt(
		signature: Bytes,
        signer: Bytes,
        message: Bytes,
		ciphertext: Bytes,
		asset_id: u32,
		secret_key: Bytes,
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
            // let asset_id_as_type = TryInto::<T::AssetId>::try_into(asset_id).ok().unwrap();
			// shouldn't make this assumption... will fix later when testing
			// let metadata = T::MetadataProvider::get(asset_id_as_type.clone()).unwrap();
			let metadata = T::MetadataProvider::get(asset_id).unwrap();
			// decrypt secret key
			return Some(Self::do_decrypt(
				acct_id, 
				ciphertext.to_vec(),
				metadata.public_key,
				sk,
			));
		}

		Some(Bytes::from(Vec::new()))
	}

	/// decrypt reencrypted data
	/// 
	/// * `account_id`: The account id of the caller requesting decryption.
	/// * `ciphertext`: The ciphertext to be decrypted
	/// * `delegating_public_key`: The delegating public key created by
	///                            to the entity that encrypted the data (i.e. data owner)
	/// * `x25518_sk`: An x25519 secret whose public key was passed via a rule executor (by the same account id
	///                passed to this function) when requesting decryption rights. 
	/// 
	fn do_decrypt(
		account_id: T::AccountId,
		ciphertext: Vec<u8>,
		delegating_public_key: Vec<u8>,
		x25519_sk: BoxSecretKey,
	) -> Bytes {
		// read runtime storage items
		// capsule
		let encryption_artifact = EncryptionArtifacts::<T>::get(delegating_public_key.clone()).unwrap();
		// 
		let reencryption_artifact = ReencryptionArtifacts::<T>::get(
			account_id.clone(), delegating_public_key.clone(),
		).unwrap();
		let encrypted_capsule_fragments = EncryptedCapsuleFrags::<T>::get(
			account_id, delegating_public_key.clone()
		);

		// gathering + formatting data
		let delegating_pk = PublicKey::from_bytes(delegating_public_key).unwrap();
		let ephemeral_pk = PublicKey::from_bytes(reencryption_artifact.ephemeral_public_key.clone()).unwrap();
		let verifying_pk = PublicKey::from_bytes(reencryption_artifact.verifying_key.clone()).unwrap();

		let capsule_data = encryption_artifact.capsule;
		let capsule = Capsule::from_bytes(&capsule_data).unwrap();
		// TODO: refactor this completely, it's pretty bad... at least move to new function
		let mut verified_capsule_fragments: Vec<VerifiedCapsuleFrag> = Vec::new();
		for enc_cap_frag in encrypted_capsule_fragments.into_iter() {
			let raw_pk = enc_cap_frag.public_key.clone();
			let pk_array = iris_primitives::slice_to_array_32(&raw_pk).unwrap();
			let cap_pk = BoxPublicKey::from(*pk_array);
			let decrypted_capsule_vec = iris_primitives::decrypt_x25519(
				cap_pk,
				x25519_sk.clone(),
				enc_cap_frag.ciphertext.clone(),
				enc_cap_frag.nonce.clone(),
			).unwrap();
			let cfrag = CapsuleFrag::from_bytes(decrypted_capsule_vec).unwrap();
			// verify each capsule fragment
			let verified_cfrag = cfrag
				.verify(&capsule, &verifying_pk, &delegating_pk, &ephemeral_pk)
				.unwrap();
			verified_capsule_fragments.push(verified_cfrag);
		}
		// ----------------
		// the public key associated with secret that encrypted the cfrags
		// TODO: need to make better utility funcs to shorten this
		let pk = iris_primitives::vec_to_box_public_key(&reencryption_artifact.secret.public_key);
		// recover secret key created by PROXY node and whose PK was used to generate kfrags
		let decrypted_tpre_sk_bytes = iris_primitives::decrypt_x25519(
			pk,
			x25519_sk,
			reencryption_artifact.secret.ciphertext.clone(),
			reencryption_artifact.secret.nonce,
		).unwrap();
		let decrypted_sk = SecretKey::from_bytes(decrypted_tpre_sk_bytes).unwrap();
		// ----------------
		// here, the secret key should be the secret key whose pk was used to generate kfrags
		// and the pub key should be the one whose sk created the frags
		let plaintext = match umbral_pre::decrypt_reencrypted(
			&decrypted_sk,
			&delegating_pk,
			&capsule,
			verified_capsule_fragments, 
			ciphertext,
		) {
			Ok(plaintext) => plaintext.to_vec(),
			Err(e) => {
				log::error!("An error occurred while decrypting the provided ciphertext: {:?}", e);
				"".as_bytes().to_vec()
			}
		};
		Bytes::from(plaintext)
	}

	/// TODO: look at client\network\src\config.rs for sk generation/storage + write to file
    /// Recover signing acct and use it to encrypt the data and submit unsigned tx
	/// 
	/// * `plaintext`: the plaintext to encrypt
	/// * `signature`: The signature used to sign the message
	/// * `signer`: The signing account id
	/// * `message`: The signed message
	/// * `proxy`: A proxy node's account id
	/// 
    pub fn encrypt(
        plaintext: Bytes,
        signature: Bytes,
        signer: Bytes,
        message: Bytes,
        proxy: Bytes,
    ) -> Bytes {
        let proxy_acct_bytes: [u8;32] = proxy.to_vec().try_into().unwrap();
        let proxy_acct_id: T::AccountId = T::AccountId::decode(&mut &proxy_acct_bytes[..]).unwrap();

        let acct_bytes: [u8;32] = signer.to_vec().try_into().unwrap();
        let acct_pubkey = Public::from_raw(acct_bytes);

        let sig: Signature = Signature::from_slice(signature.to_vec().as_ref()).unwrap();
        let msg: Vec<u8> = message.to_vec();

        let acct_id: T::AccountId = T::AccountId::decode(&mut &acct_bytes[..]).unwrap();

        if sig.verify(msg.as_slice(), &acct_pubkey) {
            let plaintext_as_slice: &[u8] = &plaintext;
			return Self::do_encrypt(plaintext_as_slice, acct_id, proxy_acct_id);
        }

        Bytes::from(b"Signature verification failed".to_vec())
    }

	fn do_encrypt(
		plaintext: &[u8],
		owner_account_id: T::AccountId,
		proxy_account_id: T::AccountId,
	) -> Bytes {
		let proxy_pk_vec = pallet_authorities::Pallet::<T>::x25519_public_keys(proxy_account_id.clone());
		// TODO: Error handling! Only works if proxy has a key
		let proxy_pk_slice = iris_primitives::slice_to_array_32(&proxy_pk_vec).unwrap();
		let proxy_pk = BoxPublicKey::from(*proxy_pk_slice);
		
		let phrase = b"iris encryption";
		let (seed, _) = T::Randomness::random(phrase);
		// seed needs to be guaranteed to be 32 bytes.
		let seed = <[u8; 32]>::decode(&mut TrailingZeroInput::new(seed.as_ref()))
			.expect("input is padded with zeroes; qed");
		let mut rng = ChaCha20Rng::from_seed(seed);
		let sk = SecretKey::random_with_rng(rng.clone());
		let pk = sk.public_key();
		let (capsule, ciphertext) = match umbral_pre::encrypt_with_rng(
			&mut rng, &pk, plaintext)
		{
			Ok((capsule, ciphertext)) => (capsule, ciphertext),
			Err(e) => {
				log::error!("Something went wrong while encrypting the data: {:?}", e);
				return Bytes::from("".as_bytes().to_vec());
				// return Err(error);
			}
		};
	
		let sk_bytes = sk.to_secret_array().as_secret().to_vec();
		let encrypted_sk = encrypt_x25519(proxy_pk, sk_bytes);
		let call = Call::submit_encryption_artifacts { 
			owner: owner_account_id,
			proxy: proxy_account_id,
			capsule: capsule.clone().to_array().as_slice().to_vec(),
			public_key: pk.clone().to_array().as_slice().to_vec(),
			encrypted_sk_box: encrypted_sk,
		};

		match SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into()) {
			Ok(_) => {
				Bytes::from(ciphertext.to_vec())
			},
			Err(e) => {
				log::error!("Something went wrong while submitting the unsigned transaction: {:?}", e);
				Bytes::from(b"An error occurred while submitting the unsigned tx. Please try again. If the issue persists, restart your node and try again.".to_vec())
			}
		}
	
	}

	/// A proxy processes requests to generate kfrags for an authorized caller
	/// 
	/// * `account`: The account of the proxy node to execute commands and submit results
	///
	fn proxy_process_kfrag_generation_requests(
		account: T::AccountId,
		candidates: Vec<T::AccountId>,
	) -> Result<(), Error<T>> {
		let kfrag_generation_requests = KeyFragGenerationRequests::<T>::get(account.clone());
		let secret_storage = StorageValueRef::persistent(b"iris::x25519");
		if let Ok(Some(local_sk)) = secret_storage.get::<[u8;32]>() {
			let local_secret_key: BoxSecretKey = BoxSecretKey::from(local_sk);
			for request in kfrag_generation_requests.into_iter() {
				// ---------
				// 1. recover secret key needed to generate kfrags
				let encrypted_delegating_sk = ProxyCodes::<T>::get(
					account.clone(), 
					request.data_public_key.clone()
				).unwrap();
				ensure!(encrypted_delegating_sk.public_key.len() == 32, Error::<T>::InvalidPublicKeyLength);
				// convert pk vec to BoxPublicKey
				let encrypted_sk_pub_key: BoxPublicKey = iris_primitives::vec_to_box_public_key(
					&encrypted_delegating_sk.public_key.clone()
				);
				// TODO ERROR HANDLING?
				let delegating_sk_bytes = iris_primitives::decrypt_x25519(
					encrypted_sk_pub_key.clone(),
					local_secret_key.clone(),
					encrypted_delegating_sk.ciphertext.clone(),
					encrypted_delegating_sk.nonce.clone(),
				).unwrap();
				let delegating_secret_key = SecretKey::from_bytes(delegating_sk_bytes).unwrap();
				// ---------
				// generate new key pair 
				
				let phrase = b"iris reencapsulation";
				let (seed, _) = T::Randomness::random(phrase);
				// seed needs to be guaranteed to be 32 bytes.
				let seed = <[u8; 32]>::decode(&mut TrailingZeroInput::new(seed.as_ref()))
					.expect("input is padded with zeroes; qed");
				let mut rng = ChaCha20Rng::from_seed(seed);

				let signer = umbral_pre::Signer::new(delegating_secret_key.clone());
				let receiving_sk = SecretKey::random_with_rng(rng.clone());
				let receiving_pk = receiving_sk.public_key();
				// generate kfrags
				// TODO: store/pass threshold + shares values? hard coded at {3, 2} currently
				let kfrags = generate_kfrags_with_rng(
				    &mut rng, 
					&delegating_secret_key.clone(), // this is the original SK generated by the data owner
					&receiving_pk.clone(), // newly generated ephemeral public key
					&signer, 
					2, 3, true, true
				);
				// ----------
				let mut assignments = Vec::new();
				let required_authorities_count = kfrags.len();
				// this seems like it should come a lot earlier, or not be made here at all
				// still need to refactor
				ensure!(candidates.len() >= required_authorities_count, Error::<T>::InsufficientAuthorities);
				for i in 0..required_authorities_count {
					let candidate = candidates[i].clone();
					// get x25519 pk
					let recipient_pk_vec = pallet_authorities::Pallet::<T>::x25519_public_keys(candidate.clone());
					let recipient_pk = iris_primitives::vec_to_box_public_key(&recipient_pk_vec);
					let key_fragment = kfrags[i].clone()
						.unverify().to_array()
						.as_slice().to_vec();
					// Do I really need to do this?
					let encrypted_kfrag_data = iris_primitives::encrypt_x25519(
						recipient_pk.clone(), key_fragment,
					);
					assignments.push((candidate.clone(), encrypted_kfrag_data.clone()));
				}
				// passed as arg
				let recipient_pk: BoxPublicKey = iris_primitives::vec_to_box_public_key(
					&request.consumer_public_key.clone()
				);
				let receiving_sk_bytes = receiving_sk.to_secret_array()
					.as_secret()
					.to_vec();
				let encrypted_ephem_sk_artifacts = iris_primitives::encrypt_x25519(
					recipient_pk, receiving_sk_bytes,
				);
				// ----------
				// send signed tx to encode this on chain (potentially acting in capacity of proxy (substrate version))
				let tx_signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
				if !tx_signer.can_sign() {
					log::error!(
						"No local accounts available. Consider adding one via `author_insertKey` RPC.",
					);
				}
				let _results = tx_signer.send_signed_transaction(|_account| {
					Call::submit_reencryption_keys {
						consumer: request.caller.clone(),
						receiving_public_key: receiving_pk.clone().to_array().to_vec(),
						delegating_public_key: request.data_public_key.clone(), 
						encrypted_receiving_sk: encrypted_ephem_sk_artifacts.clone(),
						verifying_public_key: signer.verifying_key().to_array().to_vec(),
						consumer_public_key: request.consumer_public_key.clone(),
						kfrag_assignments: assignments.clone(),
					}
				});
			}	
		}
		Ok(())
	}

	/// kfrag holders execute this logic to reencrypt for a caller
	fn kfrag_holder_process_reencryption_requests(
		account: T::AccountId,
	) -> Result<(), Error<T>> {
		let reencryption_requests = 
			CapsuleFragmentGenerationRequests::<T>::get(account.clone());
		
		let secret_storage = StorageValueRef::persistent(b"iris::x25519");
		// only proceed if we have the secret key
		if let Ok(Some(local_sk)) = secret_storage.get::<[u8;32]>() {
			let local_secret_key: BoxSecretKey = BoxSecretKey::from(local_sk);
			// each request contains (caller (consumer), data_public_key, caller_public_key)
			for request in reencryption_requests.iter() {
				// ----------
				let encryption_artifacts = EncryptionArtifacts::<T>::get(request.data_public_key.clone()).unwrap();
				let reencryption_artifact: ReencryptionArtifact<T::AccountId> = ReencryptionArtifacts::<T>::get(
					request.caller.clone(), request.data_public_key.clone()
				).unwrap();
				// TODO: not very safe but should work for now
				let encrypted_frag = &reencryption_artifact.verified_kfrags.clone()
					.iter()
					.filter(|k| k.0 == account.clone())
					.map(|k| k.1.clone())
					.collect::<Vec<_>>()[0];

				// convert to PublicKey
				let enc_pk_temp = encrypted_frag.public_key.clone();
				let pk_array = iris_primitives::slice_to_array_32(&enc_pk_temp).unwrap();
				let kfrag_enc_public_key = BoxPublicKey::from(*pk_array);
				// decrypt encrypted kfrag
				let kfrag_bytes = iris_primitives::decrypt_x25519(
					kfrag_enc_public_key, 
					local_secret_key.clone(), 
					encrypted_frag.ciphertext.to_vec(), 
					encrypted_frag.nonce.to_vec()
				).unwrap();
				let kfrag = KeyFrag::from_bytes(kfrag_bytes).unwrap();

				// ----------
				// KEY FRAGMENT VERIFICATION
				// "PK_d"
				let data_public_key = PublicKey::from_bytes(&request.data_public_key.clone()).unwrap();
				// "PK_{ephem, C}"
				let consumer_public_key = PublicKey::from_bytes(
					&reencryption_artifact.ephemeral_public_key.clone()
				).unwrap();
				// "PK_signer"
				let verifying_pk = PublicKey::from_bytes(reencryption_artifact.verifying_key.clone()).unwrap();
				let verified_kfrag = kfrag.verify(&verifying_pk, Some(&data_public_key), Some(&consumer_public_key)).unwrap();
				// ----------
				// create capsule fragment
				let phrase = b"iris reencryption";
				let (seed, _) = T::Randomness::random(phrase);
				// seed needs to be guaranteed to be 32 bytes.
				let seed = <[u8; 32]>::decode(&mut TrailingZeroInput::new(seed.as_ref()))
					.expect("input is padded with zeroes; qed");
				let mut rng = ChaCha20Rng::from_seed(seed);
				// recover capsule and pk (created by data owner)
				let capsule_data = encryption_artifacts.capsule.clone();
				let capsule = Capsule::from_bytes(&capsule_data).unwrap();
				// generate a capsule fragment
				let verified_cfrag = reencrypt_with_rng(&mut rng, &capsule, verified_kfrag);
				// convert to bytes and encrypt
				let cfrag_bytes = verified_cfrag.to_array().as_slice().to_vec();
				let enc_caller_pk_temp = request.caller_public_key.clone();
				let caller_pk_array = iris_primitives::slice_to_array_32(&enc_caller_pk_temp).unwrap();
				let caller_pk = BoxPublicKey::from(*caller_pk_array);

				let encrypted_cfrag_data = iris_primitives::encrypt_x25519(
					caller_pk, cfrag_bytes,
				);
				// ----------
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

	fn validate_transaction_parameters() -> TransactionValidity {
		ValidTransaction::with_tag_prefix("iris")
			.priority(2 << 20)
			.longevity(5)
			.propagate(true)
			.build()
	}

	// what if public_key dne?
	pub fn add_kfrag_request(
        account: T::AccountId,
        data_public_key: Vec<u8>,
		consumer_public_key: Vec<u8>,
    ) {
        // NOTE: this assumes there's at least one proxy available.
        // TODO: revisit this when testing
        let proxy = EncryptionArtifacts::<T>::get(data_public_key.clone()).unwrap().proxy;
        KeyFragGenerationRequests::<T>::mutate(proxy, |pks| {
            pks.push(KeyFragGenerationRequest {
                caller: account,
                data_public_key: data_public_key.clone(),
				consumer_public_key: consumer_public_key.clone(),
            });
        });
    }
}

pub trait OffchainKeyManager<AccountId> {
	fn process_decryption_delegation(
		account: AccountId,
		candidates: Vec<AccountId>,
	);
	fn process_reencryption_requests(account: AccountId);
}

impl<T: Config> OffchainKeyManager<T::AccountId> for Pallet<T> {
	fn process_decryption_delegation(
		account: T::AccountId,
		candidates: Vec<T::AccountId>
	) {
		// TODO: proper error handling
		Self::proxy_process_kfrag_generation_requests(account, candidates)
			.expect("reencryption should work");
	}

	fn process_reencryption_requests(account: T::AccountId) {
		Self::kfrag_holder_process_reencryption_requests(account)
			.expect("reencapsulation should work");
	}
}
