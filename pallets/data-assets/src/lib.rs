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
use codec::{Encode, Decode, HasCompact};
use frame_support::ensure;
use frame_support::pallet_prelude::*;
use frame_system::{
    self as system, ensure_signed, pallet_prelude::*,
};

use sp_core::{
    offchain::{StorageKind},
    Bytes,
};

use sp_runtime::{
    RuntimeDebug,
    traits::{AtLeast32BitUnsigned, StaticLookup, One},
};
use sp_std::{
    prelude::*,
};

use core::convert::TryInto;
use iris_primitives::IngestionCommand;

#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub struct EjectionCommand {

}

#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub enum DataCommand<LookupSource, AssetId, Balance, AccountId> {
    /// (ipfs_address, cid, requesting node address, asset id, balance, dataspace_id)
    AddBytes(Vec<u8>, Vec<u8>, LookupSource, AssetId, Balance, AssetId),
    /// (requestor, owner, assetid)
    CatBytes(AccountId, AccountId, AssetId),
    /// (node, assetid, CID)
    PinCID(AccountId, AssetId, Vec<u8>),
    /// asset id, lsit of dataspace ids
    AddToDataSpace(AssetId, AssetId),
}

/// struct to store metadata of an asset class
#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub struct AssetMetadata {
    /// the cid of some data
    pub cid: Vec<u8>,
}

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
	use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
	use frame_system::{
        pallet_prelude::*,
    };
	use sp_std::{
        str,
    };

	#[pallet::config]
    /// the module configuration trait
	pub trait Config: frame_system::Config + pallet_assets::Config
    {
        /// The overarching event type
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        /// the overarching call type
	    type Call: From<Call<Self>>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
	pub struct Pallet<T>(_);

    /// A queue of data to publish or obtain on IPFS.
    /// Commands are processed by offchain workers (of validators) in the iris-session pallet
	#[pallet::storage]
	pub(super) type IngestionQueue<T: Config> = StorageValue<
        _, Vec<IngestionCommand<T::AccountId, T::AssetId, T::Balance>>, ValueQuery,
    >;

    #[pallet::storage]
    pub(super) type NextAssetId<T: Config> = StorageValue<_, T::AssetId, ValueQuery>;

	#[pallet::storage]
    #[pallet::getter(fn ejection_queue)]
	pub(super) type EjectionQueue<T: Config> = StorageValue<
        _,
        Vec<DataCommand<
            <T::Lookup as StaticLookup>::Source, 
            T::AssetId,
            T::Balance,
            T::AccountId>
        >,
        ValueQuery,
    >;

    /// A collection of asset ids
    /// TODO: currently allows customized asset ids but in the future
    /// we can use this to dynamically generate unique asset ids for content
    #[pallet::storage]
    #[pallet::getter(fn asset_ids)]
    pub(super) type AssetIds<T: Config> = StorageValue<
        _,
        Vec<T::AssetId>,
        ValueQuery,
    >;

    // map asset id to (cid, dataspaces)
    #[pallet::storage]
    #[pallet::getter(fn metadata)]
    pub(super) type Metadata<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AssetId,
        AssetMetadata,
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

    #[pallet::genesis_config]
    pub struct GenesisConfig {
        pub initial_asset_id: u32,
    }

    #[cfg(feature = "std")]
    impl Default for GenesisConfig {
        fn default() -> Self {
            GenesisConfig {
                initial_asset_id: 2,
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig {
        fn build(&self) {
            let asset_id = TryInto::<T::AssetId>::try_into(self.initial_asset_id).ok().unwrap();
            NextAssetId::<T>::put(asset_id);
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
         fn on_initialize(block_number: T::BlockNumber) -> Weight {
            // needs to be synchronized with offchain_worker actitivies
            if block_number % 2u32.into() == 1u32.into() {
                // <IngestionQueue<T>>::kill();
                <EjectionQueue<T>>::kill();
            }

            0
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
        pub fn request_ingestion(
            origin: OriginFor<T>,
            admin: <T::Lookup as StaticLookup>::Source,
            cid: Vec<u8>,
            multiaddress: Vec<u8>,
            estimated_size_gb: u128,
            #[pallet::compact] dataspace_id: T::AssetId,
            #[pallet::compact] reserve_balance: T::Balance,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            // check that the caller has access to the dataspace
            // let balance = <pallet_assets::Pallet<T>>::balance(dataspace_id.clone(), who.clone());
            // let balance_primitive = TryInto::<u128>::try_into(balance).ok();
            // ensure!(balance_primitive != Some(0), Error::<T>::DataSpaceNotAccessible);
            // TODO: Generate a unique asset id
            // let staking_id = b"12345678";
            // TODO: I need to figure out how to make this unlockable given 
            // a condition... basically unlockable by consensus? idk... 
            // if the command is processed, this should be unlocked + distributed to gateways
            // T::Currency::set_lock(STAKING_ID, &who, reserve_balance, WithdrawReasons::all());
            // push a new command to the ingestion queue
            <IngestionQueue<T>>::mutate(|q| {
                q.push(
                    IngestionCommand {
                        owner: who.clone(),
                        cid: cid,
                        multiaddress: multiaddress,
                        estimated_size_gb: estimated_size_gb,
                        dataspace_id: dataspace_id,
                        balance: reserve_balance,
                    }
                );
            });
            Self::deposit_event(Event::CreatedIngestionRequest);
			Ok(())
        }
    
        /// Create a new asset class on behalf of an admin node
        /// and submit a request to associate it with the specified dataspace
        /// 
        /// TODO: this is obviously insecure at the moment, as it is callable by
        /// any node. We will resolve this issue at a later date (once we have zk snarks)
        /// Technically, this function allows anyone to freely create 
        /// a new asset on someone's behalf
        ///
        /// * `admin`: The admin account
        /// * `cid`: The cid generated by the OCW
        /// * `dataspace_id`: The dataspace that the newly created asset class should be 
        ///                   associated with
        /// * `id`: The AssetId (passed through from the create_storage_asset call)
        /// * `balance`: The balance (passed through from the create_storage_asset call)
        ///
        #[pallet::weight(100)]
        pub fn submit_ipfs_add_results(
            origin: OriginFor<T>,
            admin: <T::Lookup as StaticLookup>::Source,
            cid: Vec<u8>,
            occ_id: Vec<u8>,
            dataspace_id: T::AssetId,
            #[pallet::compact] id: T::AssetId,
            #[pallet::compact] balance: T::Balance,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            let which_admin = T::Lookup::lookup(admin.clone())?;
            // let new_origin = system::RawOrigin::Signed(which_admin.clone()).into();

            // <pallet_assets::Pallet<T>>::create(new_origin, id.clone(), admin.clone(), balance)
            //     .map_err(|_| Error::<T>::CantCreateAssetClass)?;

            // let mut pending_dataspace_vec = Vec::new();
            // pending_dataspace_vec.push(dataspace_id.clone());
            // insert into metadata for the asset class for the first time
            <Metadata<T>>::insert(id.clone(), AssetMetadata {
                cid: cid.clone(),
            });
            // TOOD: This should be its own queue
            // dispatch update dataspace metadata command
            <EjectionQueue<T>>::mutate(
                |queue| queue.push(DataCommand::AddToDataSpace( 
                    id.clone(),
                    dataspace_id.clone(),
                )));
            // <AssetIds<T>>::mutate(|ids| ids.push(id.clone()));
            
            Self::deposit_event(Event::AssetClassCreated(id.clone()));
            
            Ok(())
        }
	}
}

impl<T: Config> Pallet<T> {
    fn create_asset_class(
        origin: OriginFor<T>,
        admin: <T::Lookup as StaticLookup>::Source,
        asset_id: T::AssetId,
        cid: Vec<u8>,
        balance: T::Balance,
    ) -> DispatchResult {
        // <pallet_assets::Pallet<T>>::create(origin, asset_id.clone(), admin.clone(), balance)
        //         .map_err(|_| Error::<T>::CantCreateAssetClass)?;
        <Metadata<T>>::insert(asset_id.clone(), AssetMetadata {
            cid: cid.clone(),
        });
        Ok(())
    }

    // a super simple asset id generator and mutator
    // needs to be modified so we don't have duplicate asset ids
    fn next_asset_id() -> T::AssetId {
        let mut next = NextAssetId::<T>::get();
        let primitive = TryInto::<u32>::try_into(next).ok().unwrap();
        let new_id = primitive + 1u32;
        let new_next_asset_id = TryInto::<T::AssetId>::try_into(primitive).ok().unwrap();
        NextAssetId::<T>::mutate(|id| *id = new_next_asset_id);
        next
    }

}

/// a trait to provide the ingestion queue to other modules
pub trait QueueProvider<AccountId, AssetId, Balance> {
    fn ingestion_queue() -> Vec<IngestionCommand<AccountId, AssetId, Balance>>;
    fn kill_ingestion_queue();
}

impl<T: Config> QueueProvider<T::AccountId, T::AssetId, T::Balance> for Pallet<T> {
    fn ingestion_queue() -> Vec<IngestionCommand<T::AccountId, T::AssetId, T::Balance>> {
        IngestionQueue::<T>::get()
    }
    fn kill_ingestion_queue() {
        IngestionQueue::<T>::kill();
    }
}

use frame_system::Origin;
use frame_system::{
    pallet_prelude::*,
};

/// The result handler allows other modules to submit "execution"
/// of commands added to the queue
/// honestly at this point... it almost seems like it'd make more sense to bake all this
/// into the consensus mechanism itself, i.e. babe/aura
/// basically I'm implementing a parallel consensus mechanism to determine who gets to proxy requests
pub trait ResultHandler<T: frame_system::Config, AssetId, Balance> {
    fn create_asset_class(
        origin: OriginFor<T>,
        admin: <T::Lookup as StaticLookup>::Source,
        cid: Vec<u8>,
        balance: Balance,
    ) -> DispatchResult;
}

impl<T: Config> ResultHandler<T, T::AssetId, T::Balance> for Pallet<T> {
    // this is just an extrinsic...
    fn create_asset_class(
        origin: OriginFor<T>,
        admin: <T::Lookup as StaticLookup>::Source,
        cid: Vec<u8>,
        balance: T::Balance,
    ) -> DispatchResult {
        let asset_id = Self::next_asset_id();
        log::info!("CREATING NEW ASSET CLASS WITH ID: {:?}", asset_id);
        <pallet_assets::Pallet<T>>::create(origin, asset_id.clone(), admin.clone(), balance)
            .map_err(|e| {
                log::info!("Failed to create asset class due to error: {:?}", e);
                return Error::<T>::CantCreateAssetClass;
            })?;
        log::info!("Writing to Metadata");
        <Metadata<T>>::insert(asset_id.clone(), AssetMetadata {
            cid: cid.clone(),
        });
        Ok(())
    }
}