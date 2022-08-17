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
use frame_support::{
    ensure,
    pallet_prelude::*,
    traits::{Currency, LockableCurrency},
};
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
use pallet_vesting::VestingInfo;
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
	use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
	use frame_system::{
        pallet_prelude::*,
    };
	use sp_std::{
        str,
    };

	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_assets::Config + pallet_vesting::Config
    {
        /// The overarching event type
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        /// the overarching call type
	    type Call: From<Call<Self>>;
        /// The currency trait.
		type Currency: LockableCurrency<Self::AccountId>;
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

    // map asset id to (cid, dataspaces)
    #[pallet::storage]
    #[pallet::getter(fn metadata)]
    pub(super) type Metadata<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AssetId,
        AssetMetadata,
    >;

    #[pallet::storage]
    pub type Delay<T: Config> = StorageValue<_, u32, ValueQuery>;

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
        pub delay: u32,
    }

    #[cfg(feature = "std")]
    impl Default for GenesisConfig {
        fn default() -> Self {
            GenesisConfig {
                initial_asset_id: 2,
                delay: 10,
            }
        }
    }

    #[pallet::genesis_build]
    impl<T: Config> GenesisBuild<T> for GenesisConfig {
        fn build(&self) {
            let asset_id = TryInto::<T::AssetId>::try_into(self.initial_asset_id).ok().unwrap();
            NextAssetId::<T>::put(asset_id);
            Delay::<T>::put(self.delay);
        }
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
         fn on_initialize(block_number: T::BlockNumber) -> Weight {
            // needs to be synchronized with offchain_worker actitivies
            if block_number % 2u32.into() == 1u32.into() {
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
            gateway: <T::Lookup as StaticLookup>::Source,
            gateway_reserve: BalanceOf<T>,
            cid: Vec<u8>,
            multiaddress: Vec<u8>,
            estimated_size_gb: u128,
            #[pallet::compact] min_asset_balance: T::Balance,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let g = T::Lookup::lookup(gateway.clone())?;
            let mut commands = IngestionCommands::<T>::get(g);
            let cmd = IngestionCommand {
                owner: who.clone(),
                cid: cid,
                multiaddress: multiaddress,
                estimated_size_gb: estimated_size_gb,
                balance: min_asset_balance,
            };
            commands.push(cmd.clone());
            let current_block_number = <frame_system::Pallet<T>>::block_number();
            let target_block = current_block_number + Delay::<T>::get().into();
            // we need to store this info somewhere...
            // then in the OCW, check which commands are associated with (the block prior to??)the target block
            // if not executed, then we need to undo the vesting/destroy the vesting schedule

            let new_origin = system::RawOrigin::Signed(who.clone()).into();
            // vest currency
            <pallet_vesting::Pallet<T>>::vested_transfer(
                new_origin, gateway, 
                VestingInfo::new(gateway_reserve, gateway_reserve, target_block),
            )?;
            Self::deposit_event(Event::CreatedIngestionRequest);
			Ok(())
        }
	}
}

impl<T: Config> Pallet<T> {
    // a super simple asset id generator and mutator
    // needs to be modified so we don't have duplicate asset ids
    fn next_asset_id() -> T::AssetId {
        let mut next = NextAssetId::<T>::get();
        let primitive = TryInto::<u32>::try_into(next).ok().unwrap();
        let new_id = primitive + 1u32;
        let new_next_asset_id = TryInto::<T::AssetId>::try_into(new_id).ok().unwrap();
        NextAssetId::<T>::mutate(|id| *id = new_next_asset_id);
        next
    }
}

/// a trait to provide the ingestion queue to other modules
pub trait QueueProvider<AccountId, Balance> {
    fn ingestion_requests(gateway: AccountId) -> Vec<IngestionCommand<AccountId, Balance>>;
}

impl<T: Config> QueueProvider<T::AccountId, T::Balance> for Pallet<T> {
    fn ingestion_requests(gateway: T::AccountId) -> Vec<IngestionCommand<T::AccountId, T::Balance>> {
        IngestionCommands::<T>::get(gateway)
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
        let asset_id = Self::next_asset_id();
        let admin = T::Lookup::unlookup(cmd.clone().owner);
        let new_origin = system::RawOrigin::Signed(who.clone()).into();
        <pallet_assets::Pallet<T>>::create(new_origin, asset_id.clone(), admin.clone(), cmd.balance.clone())
            .map_err(|e| {
                log::info!("Failed to create asset class due to error: {:?}", e);
                return Error::<T>::CantCreateAssetClass;
            })?;
        <Metadata<T>>::insert(asset_id.clone(), AssetMetadata { cid: cmd.cid.clone() });
        // remove from ingestion commands, this must be done before the 'now + delay' number of blocks passes
        // for now... let's just assume there is not time limit and test it out
        let mut cmds = IngestionCommands::<T>::get(who.clone());
        let cmd_idx = cmds.iter().position(|c| *c == cmd.clone()).unwrap();
        cmds.remove(cmd_idx);
        IngestionCommands::<T>::insert(who.clone(), cmds);
        // emit event?
        Ok(())
    }
}