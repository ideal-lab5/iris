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

//! # Data Assets Pallet
//!
//! ## Overview
//!
//! ### Goals
//! 
//! This module enables data ingestion into Iris by providing the 
//! ability to construct a request to a gateway node to ingest data 
//! that has been staged through this pallet. Here, by staging we mean
//! the ingestion staging map, which only stages the public key used to encrypt the data.
//! 
//! This pallet also tracks and updates asset ids for newly create data asset classes 
//! and provides functionality to create new data asset classes and to track their metadata.
//! 
//! It is important to note that with the current implementation, a node
//! can only stage at most one ingestion request at a time.
//! 
//! ### Dispatchable Functions
//! 
//! * create_request
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
        AppCrypto, CreateSignedTransaction,
    },
};

use sp_runtime::{
    KeyTypeId,
    RuntimeDebug,
    traits::{
        Convert,
        StaticLookup,
    },
};
use sp_std::{
    prelude::*,
};
use core::convert::TryInto;
// use pallet_vesting::VestingInfo;
use iris_primitives::IngestionCommand;

/// struct to store metadata of an asset class
#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub struct AssetMetadata {
    /// the cid of some data
    pub cid: Vec<u8>,
    /// the public key associated with the encryption artifacts (capsule and fragments)
    pub public_key: Vec<u8>,
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
    #[pallet::getter(fn ingestion_commands)]
    pub(super) type IngestionCommands<T: Config> = StorageMap<
        _, 
        Blake2_128Concat,
        T::AccountId, 
        Vec<IngestionCommand<T::AccountId, T::Balance>>, 
        ValueQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn next_asset_id)]
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
    pub type AssetClassOwnership<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Vec<T::AssetId>,
        ValueQuery,
    >;

    #[pallet::storage]
    pub type Delay<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// The staging map maps account ids to the public key that 
    /// corresponds to data they've encrypted but have not yet ingested
    /// We make the assumption that a node is only allowed to stage
    /// a single encrypted dataset at once (for now, open to changing that)
    #[pallet::storage]
    #[pallet::getter(fn ingestion_staging)]
    pub type IngestionStaging<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        Vec<u8>,
        OptionQuery,
    >;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
        /// A request to add bytes was queued
        CreatedIngestionRequest,
	}

	#[pallet::error]
	pub enum Error<T> {
        InsufficientBalance,
        /// could not create a new asset
        CantCreateAssetClass,
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
        /// * `gateway`: The gateway node that should verify the data.
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
            _gateway_reserve: BalanceOf<T>,
            cid: Vec<u8>,
            multiaddress: Vec<u8>,
            #[pallet::compact] min_asset_balance: T::Balance,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let g = T::Lookup::lookup(gateway)?; 
            // first ensure that the caller has sufficent funds
            // let current_block_number = <frame_system::Pallet<T>>::block_number();
            // let target_block = current_block_number + Delay::<T>::get().into();
            // let new_origin = system::RawOrigin::Signed(who.clone()).into();
            // <pallet_vesting::Pallet<T>>::vested_transfer(
            //     new_origin, gateway, 
            //     VestingInfo::new(gateway_reserve, gateway_reserve, target_block),
            // ).map_err(|_| Error::<T>::InsufficientBalance)?;
            // issue the command
            let mut commands = IngestionCommands::<T>::get(g.clone());
            let cmd = IngestionCommand {
                owner: who,
                cid,
                multiaddress,
                balance: min_asset_balance,
            };
            commands.push(cmd);
            IngestionCommands::<T>::insert(g, commands);
            Self::deposit_event(Event::CreatedIngestionRequest);
			Ok(())
        }
        // /// increase the balance vested in the request 
        // /// sent to a gateway
        // #[pallet::weight(100)]
        // pub fn bump_request(
        //     origin: OriginFor<T>,
        //     amount: BalanceOf<T>,
        // ) -> DispatchResult {
        //     // TODO
        //     Ok(())
        // }

        // /// if a request has not been processed, 'unvest' total balance
        // #[pallet::weight(100)]
        // pub fn kill_request(
        //     origin: OriginFor<T>,
        // ) -> DispatchResult {
        //     // TODO
        //     Ok(())
        // }
    }
}

impl<T: Config> Pallet<T> {

}

/// 
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
pub trait QueueManager<AccountId, Balance> {

    fn add_ingestion_staging(owner: AccountId, public_key: Vec<u8>);
    fn ingestion_requests(gateway: AccountId) -> Vec<IngestionCommand<AccountId, Balance>>;
}

impl<T: Config> QueueManager<T::AccountId, T::Balance> for Pallet<T> {

    fn add_ingestion_staging(owner: T::AccountId, public_key: Vec<u8>) {
        IngestionStaging::<T>::insert(owner, public_key);
    }

    fn ingestion_requests(gateway: T::AccountId) -> Vec<IngestionCommand<T::AccountId, T::Balance>> {
        IngestionCommands::<T>::get(gateway)
    }
}

/// The result handler allows other modules to submit "execution"
/// of commands added to the queue
/// honestly at this point... it almost seems like it'd make more sense to bake all this
/// into the consensus mechanism itself, i.e. babe/aura
/// basically I'm implementing a parallel consensus mechanism to determine who gets to proxy requests
pub trait ResultsHandler<T: frame_system::Config, AccountId, AssetId, Balance> {

    fn create_asset_class(
        origin: OriginFor<T>,
        cmd: IngestionCommand<AccountId, Balance>,
        asset_id: AssetId,
    ) -> DispatchResult;
}

impl<T: Config> ResultsHandler<T, T::AccountId, T::AssetId, T::Balance> for Pallet<T> {

    /// Create a new data asset class
    /// 
    /// * `cmd`: The ingestion command
    /// * `asset_id`: The id to assign to the new asset class
    /// 
    fn create_asset_class(
        origin: OriginFor<T>,
        cmd: IngestionCommand<T::AccountId, T::Balance>,
        asset_id: T::AssetId,
    ) -> DispatchResult {
        let who = ensure_signed(origin)?;
        if let Some(pubkey) = IngestionStaging::<T>::get(cmd.owner.clone()) {
            let admin = T::Lookup::unlookup(cmd.owner.clone());
            let new_origin = system::RawOrigin::Signed(who.clone()).into();
            <pallet_assets::Pallet<T>>::create(new_origin, asset_id, admin, cmd.balance)
                .map_err(|e| {
                    log::info!("Failed to create asset class due to error: {:?}", e);
                    Error::<T>::CantCreateAssetClass
                })?;
            Metadata::<T>::insert(asset_id, AssetMetadata {
                cid: cmd.cid.clone(),
                public_key: pubkey,
            });
            AssetClassOwnership::<T>::mutate(cmd.owner.clone(), |ids| { ids.push(asset_id); });
            IngestionStaging::<T>::remove(cmd.owner.clone());
            IngestionCommands::<T>::mutate(who, |cmds| {
                cmds.retain(|c| *c != cmd);
            });
        }

        Ok(())
    }
}