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
#![cfg_attr(not(feature = "std"), no_std)]

//! # Iris Assets Pallet
//!
//! ## Overview
//!
//! ### Goals
//! The Iris module provides functionality for creation and 
//! management of storage assets and access management
//! 
//! ### Dispatchable Functions 
//!
//! #### Permissionless functions
//! * create_storage_asset
//!
//! #### Permissioned Functions
//! * mint_tickets
//!

use scale_info::TypeInfo;
use codec::{Encode, Decode};
use frame_support::{
    pallet_prelude::*,
    traits::{Currency, LockableCurrency},
};
use frame_system::{
    self as system, 
    ensure_signed, 
    pallet_prelude::*,
    offchain::{
        AppCrypto, CreateSignedTransaction, SendUnsignedTransaction, SignedPayload, SubmitTransaction,
    },
};

use sp_runtime::{
    KeyTypeId,
    RuntimeDebug,
    traits::{
        Convert,
        StaticLookup,
        Verify,
    },
    transaction_validity::{
        InvalidTransaction, 
        TransactionValidity, 
        ValidTransaction
    },
};
use sp_std::{
    prelude::*,
};

use scale_info::prelude::string::ToString;
use sp_runtime::offchain::storage::StorageValueRef;
use generic_array::{
    GenericArray,
    typenum::UTerm,
};

use sp_core::{
    Bytes,
    sr25519::{Public, Signature},
};

use umbral_pre::*;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::SeedableRng,
};
use crypto_box::{
    aead::{ AeadCore, Aead },
	SalsaBox, PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, Nonce,
};

use core::convert::TryInto;
use pallet_vesting::VestingInfo;
use iris_primitives::{IngestionCommand, EncryptionResult, EncryptedFragment};

/// struct to store metadata of an asset class
#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub struct AssetMetadata {
    /// the cid of some data
    pub cid: Vec<u8>,
    /// the public key associated with the encryption artifacts (capsule and fragments)
    pub public_key: Vec<u8>,
}

// TODO: These structs are really getting out of hand

#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub struct SecretStuff {
    pub data_capsule: Vec<u8>,
    pub sk_capsule: Vec<u8>,
    pub sk_ciphertext: Vec<u8>,
}

#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub struct EncryptedData {
    pub capsule: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

// it would make a lot of sense to make two type aliases to identify the two different keys
#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub struct CapsuleRecoveryRequest<AccountId, AssetId> {
    pub caller: AccountId,
    pub asset_id: AssetId,
    pub capsule_encryption_pk: Vec<u8>,
    pub ciphertext_encryption_pk: Vec<u8>
}

pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"iris");

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrappers.
/// We can use from supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// the types with this pallet-specific identifier.
pub mod crypto {
	use super::KEY_TYPE;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::{
		app_crypto::{app_crypto, sr25519},
		traits::Verify,
		MultiSignature, MultiSigner,
	};
	app_crypto!(sr25519, KEY_TYPE);

	pub struct TestAuthId;

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

type BalanceOf<T> =
	<<T as pallet_vesting::Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
	use frame_support::dispatch::DispatchResult;
	use sp_std::{
        str,
    };

	#[pallet::config]
	pub trait Config: frame_system::Config + 
        CreateSignedTransaction<Call<Self>> + 
        pallet_assets::Config + 
        pallet_vesting::Config +
        pallet_authorities::Config
    {
        /// The overarching event type
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        /// the overarching call type
	    type Call: From<Call<Self>>;
        /// The currency trait.
		type Currency: LockableCurrency<Self::AccountId>;
        /// the authority id used for sending signed txs
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
	pub struct Pallet<T>(_);

    #[pallet::storage]
    pub(super) type IngestionCommands<T: Config> = StorageMap<
        _, 
        Blake2_128Concat,
        T::AccountId, 
        Vec<IngestionCommand<T::AccountId, T::Balance>>, 
        ValueQuery,
    >;

    #[pallet::storage]
    pub(super) type NextAssetId<T: Config> = StorageValue<_, T::AssetId, ValueQuery>;

    // map asset id to (cid, dataspaces)
    #[pallet::storage]
    #[pallet::getter(fn metadata)]
    pub(super) type Metadata<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AssetId,
        AssetMetadata,
        OptionQuery
    >;

    #[pallet::storage]
    pub type Delay<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// The staging map maps account ids to the public key that 
    /// corresponds to data they've encrypted but have not yet ingested
    /// We make the assumption that a node is only allowed to stage
    /// a single encrypted dataset at once
    #[pallet::storage]
    pub type IngestionStaging<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Vec<u8>,
        OptionQuery,
    >;

    // TODO: Explore making types for TPREPublicKey, Ciphertext
    // maps pubkey to ciphertext/capsule
    #[pallet::storage]
    pub type Capsules<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Vec<u8>,  // public key
        SecretStuff, // capsule data 
        OptionQuery,
    >;

    #[pallet::storage]
    pub type FragmentOwnerSet<T: Config> = StorageMap<
        _, 
        Blake2_128Concat,
        Vec<u8>, // public key
        Vec<T::AccountId>, // collection of all fragment holders
        ValueQuery,
    >;

    #[pallet::storage]
    pub type Fragments<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        Vec<u8>, // public key
        Blake2_128Concat,
        T::AccountId, // the validator
        EncryptedFragment, // the information needed to decrypt encrypted fragment knowing secret key
        OptionQuery,
    >;

    /// maps a key fragment holder to a vec of public keys for which
    /// they have been tasked with recovering the capsule fragmentr
    #[pallet::storage]
    pub type CapsuleRecoveryRequests<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Vec<CapsuleRecoveryRequest<T::AccountId, T::AssetId>>,
        ValueQuery,
    >;

    #[pallet::storage]
    pub type VerifiedCapsules<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Blake2_128Concat,
        T::AssetId,
        Vec<EncryptedFragment>, // <-- TODO: should rename this struct to something more generic
        ValueQuery,
    >;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
        /// A request to add bytes was queued
        CreatedIngestionRequest,
        /// A request to retrieve bytes was queued
        QueuedDataToCat(T::AccountId),
        /// A new asset class was created (add bytes command processed)
        AssetClassCreated(T::AssetId),
        /// A new asset was created (tickets minted)
        AssetCreated(T::AssetId),
        /// An asset was burned succesfully
        AssetBurned(T::AssetId),
        /// A node has published ipfs identity results on chain
        PublishedIdentity(T::AccountId),
        /// data has been queued to be pinned by a storage node
        QueuedDataToPin,
	}

	#[pallet::error]
	pub enum Error<T> {
        PublicKeyConversionFailure,
        /// could not build the ipfs request
		CantCreateRequest,
        /// the request to IPFS timed out
        RequestTimeout,
        /// the request to IPFS failed
        RequestFailed,
        /// The tx could not be signed
        OffchainSignedTxError,
        /// you cannot sign a tx
        NoLocalAcctForSigning,
        /// could not create a new asset
        CantCreateAssetClass,
        /// could not mint a new asset
        CantMintAssets,
        /// there is no asset associated with the specified cid
        NoSuchOwnedContent,
        /// the specified asset class does not exist
        NoSuchAssetClass,
        /// the account does not have a sufficient balance
        InsufficientBalance,
        /// the asset id is unknown or you do not have access to it
        InvalidAssetId,
        DataSpaceNotAccessible,
	}

    #[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;

		/// Validate unsigned call to this module.
		///
		/// By default unsigned transactions are disallowed, but implementing the validator
		/// here we make sure that some particular calls (the ones produced by offchain worker)
		/// are being whitelisted and marked as valid.
		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            if let Call::submit_capsule_and_kfrags{ .. } = call {
				Self::validate_transaction_parameters()
			} else {
				InvalidTransaction::Call.into()
			}
		}
	}


    #[pallet::genesis_config]
    pub struct GenesisConfig<T: Config> {
        pub initial_asset_id: T::AssetId,
        pub delay: u32,
    }

    #[cfg(feature = "std")]
    impl<T: Config> Default for GenesisConfig<T> {
        fn default() -> Self {
            let base_asset_id: u32 = 2u32;
            let asset_id = TryInto::<T::AssetId>::try_into(base_asset_id).ok().unwrap();
            GenesisConfig {
                initial_asset_id: asset_id,
                delay: 10,
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
        fn build(&self) {
            NextAssetId::<T>::put(self.initial_asset_id);
            Delay::<T>::put(self.delay);
        }
    }

	#[pallet::call]
	impl<T: Config> Pallet<T> {

        /// submits an on-chain request to fetch data and add it to iris 
        /// 
        /// * `multiaddress`: the multiaddress where the data exists
        ///       example: /ip4/192.168.1.170/tcp/4001/p2p/12D3KooWMvyvKxYcy9mjbFbXcogFSCvENzQ62ogRxHKZaksFCkAp
        /// * `cid`: the cid to fetch from the multiaddress
        ///       example: QmPZv7P8nQUSh2CpqTvUeYemFyjvMjgWEs8H1Tm8b3zAm9
        /// * `dataspace_id`: The asset id of the dataspace to associate the newly created asset class with
        /// * `id`: (temp) the unique id of the asset class -> should be generated instead
        /// * `balance`: the balance the owner is willing to use to back the asset class which will be created
        ///
        #[pallet::weight(100)]
        pub fn create_request(
            origin: OriginFor<T>,
            gateway: <T::Lookup as StaticLookup>::Source,
            gateway_reserve: BalanceOf<T>,
            cid: Vec<u8>,
            multiaddress: Vec<u8>,
            estimated_size_gb: u128,
            #[pallet::compact] min_asset_balance: T::Balance,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let g = T::Lookup::lookup(gateway.clone())?; 
            let mut commands = IngestionCommands::<T>::get(g.clone());
            let cmd = IngestionCommand {
                owner: who.clone(),
                cid: cid,
                multiaddress: multiaddress,
                estimated_size_gb: estimated_size_gb,
                balance: min_asset_balance,
            };
            commands.push(cmd.clone());
            IngestionCommands::<T>::insert(g.clone(), commands);

            let current_block_number = <frame_system::Pallet<T>>::block_number();
            let target_block = current_block_number + Delay::<T>::get().into();
            // we need to store this info somewhere...
            // then in the OCW, check which commands are associated with (the block prior to??)the target block
            let new_origin = system::RawOrigin::Signed(who.clone()).into();
            // vest currency
            <pallet_vesting::Pallet<T>>::vested_transfer(
                new_origin, gateway, 
                VestingInfo::new(gateway_reserve, gateway_reserve, target_block),
            )?;
            Self::deposit_event(Event::CreatedIngestionRequest);
			Ok(())
        }

        /// increase the balance vested in the request 
        /// sent to a gateway
        #[pallet::weight(100)]
        pub fn bump_request(
            origin: OriginFor<T>,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            // TODO
            Ok(())
        }

        /// if a request has not been processed, 'unvest' total balance
        #[pallet::weight(100)]
        pub fn kill_request(
            origin: OriginFor<T>,
        ) -> DispatchResult {
            // TODO
            Ok(())
        }

        #[pallet::weight(0)]
        pub fn submit_capsule_and_kfrags(
            origin: OriginFor<T>,
            owner: T::AccountId,
            data_capsule: Vec<u8>,
            public_key: Vec<u8>,
            sk_capsule: Vec<u8>,
            sk_ciphertext: Vec<u8>,
            encrypted_kfrags: Vec<Vec<u8>>,
        ) -> DispatchResult {
            ensure_none(origin)?;
            // assign and distribute encrypted_kfrags
            let rng = ChaCha20Rng::seed_from_u64(17u64);
            let required_authorities_count = encrypted_kfrags.len();
            // TODO: should move this encryption offchain
            let authorities: Vec<T::AccountId> = pallet_authorities::Pallet::<T>::validators();
            let mut frag_holders = Vec::new();
            for i in vec![0, required_authorities_count] {
                let authority = authorities[i].clone();
                frag_holders.push(authority.clone());
                
                let pk_bytes: Vec<u8> = pallet_authorities::Pallet::<T>::public_keys(authority.clone());
                let pk_slice = Self::slice_to_array_32(&pk_bytes)?;
                let pk = BoxPublicKey::from(*pk_slice);
                let key_fragment = encrypted_kfrags[i].as_slice().to_vec();

                let encrypted_kfrag_data = Self::encrypt_kfrag_ephemeral(
                    pk_bytes.clone(), key_fragment,
                );
                Fragments::<T>::insert(public_key.clone(), authority.clone(), encrypted_kfrag_data);
            }
            FragmentOwnerSet::<T>::insert(public_key.clone(), frag_holders);

            Capsules::<T>::insert(public_key.clone(), 
                SecretStuff {
                    data_capsule,
                    sk_capsule,
                    sk_ciphertext,
            });

            IngestionStaging::<T>::insert(owner.clone(), public_key.clone());

            // TODO: emit event
            Ok(())
        }
	}
}

impl<T: Config> Pallet<T> {
    // a super simple asset id generator and mutator
    // needs to be modified so we don't have duplicate asset ids
    fn next_asset_id() -> T::AssetId {
        let next = NextAssetId::<T>::get();
        let primitive = TryInto::<u32>::try_into(next).ok().unwrap();
        let new_id = primitive + 1u32;
        let new_next_asset_id = TryInto::<T::AssetId>::try_into(new_id).ok().unwrap();
        NextAssetId::<T>::mutate(|id| *id = new_next_asset_id);
        next
    }

    /// validates if an unsigned tx is valid
    /// for now, all are valid
    fn validate_transaction_parameters() -> TransactionValidity {
		ValidTransaction::with_tag_prefix("iris")
			.longevity(5)
			.propagate(true)
			.build()
	}

    /// Recover signing acct and use it to encrypt the data and submit unsigned tx
    pub fn encrypt(
        plaintext: Bytes,
        signature: Bytes,
        signer: Bytes,
        message: Bytes,
        shares: usize,
        threshold: usize,
    ) -> Option<Bytes> {
        let acct_bytes: [u8;32] = signer.to_vec().try_into().unwrap();
        let acct_pubkey = Public::from_raw(acct_bytes);
        let sig: Signature = Signature::from_slice(signature.to_vec().as_ref()).unwrap();
        let msg: Vec<u8> = message.to_vec();

        let acct_id: T::AccountId = T::AccountId::decode(&mut &acct_bytes[..]).unwrap();

        if sig.verify(msg.as_slice(), &acct_pubkey) {
            let plaintext_as_slice: &[u8] = &plaintext.to_vec();
            return Self::do_encrypt(plaintext_as_slice, shares, threshold, acct_id);
        }

        None 
    }

    /// generates a new keypair and uses it to encrypt the plaintext
    /// also encrypts the secret key with itself and generates 'shares' keyfragments
    /// of which 'threshold' pieces are needed to re-encrypt the encrypted secret key
    ///
    /// * 'plaintext': the plaintext to encrypt
    /// * 'shares': The number of shares to create (i.e. key fragments to create and distribute)
    /// * 'threshold': The number of key fragments needed to re-encrypt the encrypted secret key
    /// * 'owner': The account id of the address that owns the plaintext
    ///
    /// return the plaintext if successful, otherwise returns None
    ///
    fn do_encrypt(
        plaintext: &[u8], 
        shares: usize, 
        threshold: usize,
        owner: T::AccountId,
    ) -> Option<Bytes> {
        let mut rng = ChaCha20Rng::seed_from_u64(17u64);
        // generate keys
        let sk = SecretKey::random_with_rng(rng.clone());
        let pk = sk.public_key();

        let (data_capsule, data_ciphertext) = match umbral_pre::encrypt_with_rng(
            &mut rng.clone(), &pk, plaintext)
        {
            Ok((capsule, ciphertext)) => (capsule, ciphertext),
            Err(error) => {
                return None;
            },
        };

        // encrypt the secret key
        let (sk_capsule, sk_ciphertext) = match umbral_pre::encrypt_with_rng(
            &mut rng.clone(), &pk, sk.to_string().as_bytes(),
        ) {
            Ok((capsule, ciphertext)) => (capsule, ciphertext),
            Err(error) => {
                return None;
            },
        };

        let signer = Signer::new(SecretKey::random_with_rng(rng.clone()));

        let verified_kfrags = generate_kfrags_with_rng(
            &mut rng.clone(), &sk, &pk, &signer, threshold, shares, true, true
        );

        let kfrag_bytes: Vec<Vec<u8>> =
            verified_kfrags.iter().map(|k| { k.to_array().as_slice().to_vec() }).collect();
        let capsule_vec: Vec<u8> = data_capsule.to_array().as_slice().to_vec();
        let pk_vec: Vec<u8> = pk.to_array().as_slice().to_vec();

        let sk_capsule_vec: Vec<u8> = sk_capsule.to_array().as_slice().to_vec();
        let sk_ciphertext_vec: Vec<u8> = sk_ciphertext.to_vec();

        let call = Call::submit_capsule_and_kfrags { 
            owner: owner,
            data_capsule: capsule_vec,
            public_key: pk_vec.clone(),
            sk_capsule: sk_capsule_vec,
            sk_ciphertext: sk_ciphertext_vec,
            encrypted_kfrags: kfrag_bytes,
        };

		SubmitTransaction::<T, Call<T>>::submit_unsigned_transaction(call.into())
			.map_err(|()| "Unable to submit unsigned transaction.");

        Some(Bytes::from(data_ciphertext.to_vec()))
    }

    fn encrypt_kfrag_ephemeral(public_key_bytes: Vec<u8>, key_fragment_bytes: Vec<u8>) -> EncryptedFragment {
        let mut rng = ChaCha20Rng::seed_from_u64(31u64);
        let ephemeral_secret_key = BoxSecretKey::generate(&mut rng);
        let pubkey_slice_32 = Self::slice_to_array_32(public_key_bytes.as_slice()).unwrap();
        let public_key = BoxPublicKey::from(*pubkey_slice_32);

        let salsa_box = SalsaBox::new(&public_key, &ephemeral_secret_key);
        let nonce = SalsaBox::generate_nonce(&mut rng);
        let p = b"test";
        let ciphertext: Vec<u8> = salsa_box.encrypt(&nonce, &p[..]).unwrap().to_vec();

        // to decrypt, the account associated with the public_key needs to know:
        // (nonce, ciphertext, ephermeral public_key)
        // so we should return some object? like...
        EncryptedFragment{ 
            nonce: nonce.as_slice().to_vec(),
            ciphertext: ciphertext,
            public_key: ephemeral_secret_key.public_key().as_bytes().to_vec()
        }
    }

    
    fn slice_to_array_32(slice: &[u8]) -> Result<&[u8; 32], Error<T>> {
        if slice.len() == 32 {
            let ptr = slice.as_ptr() as *const [u8; 32];
            unsafe {Ok(&*ptr)}
        } else {
            Err(Error::<T>::PublicKeyConversionFailure)
        }
    }
}

pub trait MetadataProvider<AssetId> {
    fn get(asset_id: AssetId) -> Option<AssetMetadata>;
}

impl<T: Config> MetadataProvider<T::AssetId> for Pallet<T> {
    fn get(asset_id: T::AssetId) -> Option<AssetMetadata> {
        Metadata::<T>::get(asset_id)
    }
}

// Implementation of Convert trait for mapping ValidatorId with AccountId.
pub struct ValidatorOf<T>(sp_std::marker::PhantomData<T>);

impl<T: Config> Convert<T::ValidatorId, Option<T::ValidatorId>> for ValidatorOf<T> {
	fn convert(account: T::ValidatorId) -> Option<T::ValidatorId> {
		Some(account)
	}
}

/// a trait to provide the ingestion queue to other modules
pub trait QueueProvider<AccountId, AssetId, Balance> {
    /// read ingestion requests issued for a specific gateway
    fn ingestion_requests(gateway: AccountId) -> Vec<IngestionCommand<AccountId, Balance>>;
    /// request that the kfrag holder recovers the capsule fragment associated with the given public key
    fn add_capsule_recovery_request(
        account: AccountId, 
        asset_id: AssetId,
        kfrag_holder: &AccountId, 
        public_key: Vec<u8>, 
        cfrag_recovery_pk: Vec<u8>
    );
    /// add a verified capsule to the verified capsules storage map
    fn add_verified_capsule(account: AccountId, asset_id: AssetId, encrypted_capsule_framgent_data: EncryptedFragment);
    fn get_capsule_recovery_requests(account: AccountId) -> Vec<CapsuleRecoveryRequest<AccountId, AssetId>>;
    /// remove the specified public key from the collection of fragments to recover
    fn remove_capsule_recovery_request(kfrag_holder: AccountId, public_key: Vec<u8>);
    /// get the holder of kfrags as identified by public key
    fn get_fragment_holders(public_key: Vec<u8>) -> Vec<AccountId>;
    fn get_kfrags(public_key: Vec<u8>, account: AccountId) -> Option<EncryptedFragment>;
    fn get_capsule(public_key: Vec<u8>) -> Option<SecretStuff>;
}

impl<T: Config> QueueProvider<T::AccountId, T::AssetId, T::Balance> for Pallet<T> {
    fn ingestion_requests(gateway: T::AccountId) -> Vec<IngestionCommand<T::AccountId, T::Balance>> {
        IngestionCommands::<T>::get(gateway)
    }

    fn add_capsule_recovery_request(
        account: T::AccountId, 
        asset_id: T::AssetId, 
        kfrag_holder: &T::AccountId, 
        public_key: Vec<u8>, 
        cfrag_recovery_pk: Vec<u8>
    ) {
        CapsuleRecoveryRequests::<T>::mutate(kfrag_holder, |mut pks| {
            pks.push(CapsuleRecoveryRequest {
                caller: account,
                asset_id: asset_id,
                capsule_encryption_pk: cfrag_recovery_pk,
                ciphertext_encryption_pk: public_key,
            });
        });
    }

    fn add_verified_capsule(account: T::AccountId, asset_id: T::AssetId, verified_cfrag_data: EncryptedFragment) {
        VerifiedCapsules::<T>::mutate(account, asset_id, |mut cfrags| {
            cfrags.push(verified_cfrag_data);
        });
    }

    fn get_capsule_recovery_requests(account: T::AccountId) -> Vec<CapsuleRecoveryRequest<T::AccountId, T::AssetId>> {
        CapsuleRecoveryRequests::<T>::get(account)
    }

    fn remove_capsule_recovery_request(kfrag_holder: T::AccountId, public_key: Vec<u8>) {
        // TODO
    }
 
    fn get_fragment_holders(public_key: Vec<u8>) -> Vec<T::AccountId> {
        FragmentOwnerSet::<T>::get(public_key)
    }
    
    fn get_kfrags(public_key: Vec<u8>, account: T::AccountId) -> Option<EncryptedFragment> {
        Fragments::<T>::get(public_key, account)
    }

    fn get_capsule(public_key: Vec<u8>) -> Option<SecretStuff> {
        Capsules::<T>::get(public_key)
    }
}

/// The result handler allows other modules to submit "execution"
/// of commands added to the queue
/// honestly at this point... it almost seems like it'd make more sense to bake all this
/// into the consensus mechanism itself, i.e. babe/aura
/// basically I'm implementing a parallel consensus mechanism to determine who gets to proxy requests
pub trait ResultsHandler<T: frame_system::Config, AccountId, Balance> {
    fn create_asset_class(
        origin: OriginFor<T>,
        cmd: IngestionCommand<AccountId, Balance>
    ) -> DispatchResult;
}

impl<T: Config> ResultsHandler<T, T::AccountId, T::Balance> for Pallet<T> {
    // this is just an extrinsic...
    fn create_asset_class(
        origin: OriginFor<T>,
        cmd: IngestionCommand<T::AccountId, T::Balance>,
    ) -> DispatchResult {
        let who = ensure_signed(origin)?;

        // verify that capsule exists (i.e. data is 'decryptable')
        match IngestionStaging::<T>::get(cmd.owner.clone()) {
            Some(pubkey) => {
                let asset_id = Self::next_asset_id();
                let admin = T::Lookup::unlookup(cmd.clone().owner);
                let new_origin = system::RawOrigin::Signed(who.clone()).into();
                <pallet_assets::Pallet<T>>::create(new_origin, asset_id.clone(), admin.clone(), cmd.balance.clone())
                    .map_err(|e| {
                        log::info!("Failed to create asset class due to error: {:?}", e);
                        return Error::<T>::CantCreateAssetClass;
                    })?;
                <Metadata<T>>::insert(asset_id.clone(), AssetMetadata {
                    cid: cmd.cid.clone(),
                    public_key: pubkey,
                });
                IngestionStaging::<T>::remove(cmd.clone().owner);
                // remove from ingestion commands, this must be done before the 'now + delay' number of blocks passes
                // for now... let's just assume there is not time limit and test it out
                let mut cmds = IngestionCommands::<T>::get(who.clone());
                let cmd_idx = cmds.iter().position(|c| *c == cmd.clone()).unwrap();
                cmds.remove(cmd_idx);
                IngestionCommands::<T>::insert(who.clone(), cmds);
                // emit event?
                Ok(())
            },
            None => {
                Ok(())
            }
        }
    }
}