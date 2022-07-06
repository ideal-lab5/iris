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

//! # Data Ejection Pallet
//! 
//! ## Goal
//! 
//! The goal of this pallet is to handle verification of access rules
//! associated with data asset classes.
//! 
//! 
//!

use sp_runtime::traits::StaticLookup;
use sp_std::{
    prelude::*,
};

use core::convert::TryInto;

use frame_system::ensure_signed;
use pallet_data_assets::DataCommand;

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
	pub trait Config: frame_system::Config + pallet_assets::Config {
        /// The overarching event type
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        /// the overarching call type
	    type Call: From<Call<Self>>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
	pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn registry)]
    pub(super) type Registry<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AssetId,
        T::AccountId,
    >;

    /// map the address -> asset_id -> status
    #[pallet::storage]
    #[pallet::getter(fn lock)]
    pub(super) type Lock<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat, 
        T::AccountId,
        Blake2_128Concat, 
        T::AssetId,
        bool,
        ValueQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn data_retrieval_queue)]
    pub(super) type DataRetrievalQueue<T: Config> = StorageValue<
        _,
        Vec<DataCommand<
            <T::Lookup as StaticLookup>::Source, 
            T::AssetId,
            T::Balance,
            T::AccountId>
        >,
        ValueQuery,
    >;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
        ExecutionSuccess,
        ExecutionFailed,
	}

	#[pallet::error]
	pub enum Error<T> {
        NoSuchOwnedAssetClass,
        NoSuchAssetClass,
        InsufficientBalance,
	}

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
         fn on_initialize(block_number: T::BlockNumber) -> Weight {
            // needs to be synchronized with offchain_worker actitivies
            if block_number % 2u32.into() == 1u32.into() {
                <DataRetrievalQueue<T>>::kill();
            }

            0
        }
    }


	#[pallet::call]
	impl<T: Config> Pallet<T> {

        /// Register a rule with your asset class
        /// 
        /// * `id`: The asset id that the rule is being registered for
        /// * `rule_executor_address`: The address of the rule executor being registered
        /// 
        #[pallet::weight(100)]
        pub fn register_rule(
            origin: OriginFor<T>,
            #[pallet::compact] id: T::AssetId,
            rule_executor_address: T::AccountId,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                Self::check_asset_class_ownership(who.clone(), id.clone()), 
                Error::<T>::NoSuchOwnedAssetClass
            );
            <Registry::<T>>::insert(id.clone(), rule_executor_address.clone());
            Ok(())
        }

        /// A function callable by contracts
        /// which allows them to submit results of execution
        /// 
        /// * `origin`: The origin of a contract
        /// * `data_consumer_address`: The address of the caller of the contract
        /// * `id`: The id of the asset for which execution is submitted
        /// * `execution_result`: The result of the execute function as reported
        ///                       by the calling contract. A 'true' value implies
        ///                       access is granted, a 'false' implies it is not.
        /// 
        #[pallet::weight(100)]
        pub fn submit_execution_results(
            origin: OriginFor<T>,
            #[pallet::compact] id: T::AssetId,
            data_consumer_address: T::AccountId,
            execution_result: bool,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            // verify that the data_consumer holds an asset from the asset class
            let balance = <pallet_assets::Pallet<T>>::balance(id.clone(), data_consumer_address.clone());
            let balance_primitive = TryInto::<u64>::try_into(balance).ok();            
            match balance_primitive {
                Some(b) => ensure!(b >= 1, Error::<T>::InsufficientBalance),
                None => {
                    return Ok(());
                }
            }
            // verify the caller is the registered rule exectuor contract
            match <Registry::<T>>::get(id.clone()) {
                Some(addr) => {
                    if addr != who.clone() { return Ok(()) }
                    // update the 'lock' for the asset id/caller combo
                    <Lock::<T>>::insert(
                        &data_consumer_address, &id, execution_result
                    );
                    if execution_result {
                        // submit request to data retrieval queue
                        match <pallet_assets::Pallet<T>>::asset(id.clone()) {
                            Some(addr) => {
                                <DataRetrievalQueue<T>>::mutate(
                                    |queue| queue.push(DataCommand::CatBytes(
                                        who.clone(),
                                        addr.owner.clone(),
                                        id.clone(),
                                    )));
                            },
                            None => {
                                return Ok(());
                            }
                        }
                    }
                },
                None => { return Ok(()) }
            }

			Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {

    /// Check if an address is the owner of an asset id
    /// if not the owner or dne, then return false
    /// if owner, return true
    /// 
    /// * `who`: The address to check ownership for
    /// * `id`: The asset id to check ownership for
    /// 
    fn check_asset_class_ownership(
        who: T::AccountId,
        id: T::AssetId,
    ) -> bool {
        let opt_asset = <pallet_assets::Pallet<T>>::asset(id.clone());
        match opt_asset {
            Some(owned) => owned.owner == who.clone(),
            None => false
        }
    }
}