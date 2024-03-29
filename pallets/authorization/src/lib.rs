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

//! # Authorization Pallet
//! 
//! ## Goal
//! 
//! The goal of this pallet is to handle verification of access rules
//! associated with data asset classes. Rule executor contracts call into the extrinsics exposed
//! by this pallet to provide proof of accessibility for 
//! 
//!

use sp_std::{
    prelude::*,
};
use frame_support::traits::ValidatorSetWithIdentification;
use core::convert::TryInto;
use frame_system::ensure_signed;

use pallet_data_assets::MetadataProvider;
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
	pub trait Config: frame_system::Config + pallet_assets::Config + pallet_authorities::Config + pallet_iris_proxy::Config {
        /// The overarching event type
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        /// the overarching call type
	    type Call: From<Call<Self>>;
        /// A type for retrieving the validators supposed to be online in a session.
		type ValidatorSet: ValidatorSetWithIdentification<Self::AccountId>;
        /// provides asset metadata
		type MetadataProvider: pallet_data_assets::MetadataProvider<Self::AssetId>;
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
        InvalidRuleExecutor,
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
                Self::check_asset_class_ownership(who, id), 
                Error::<T>::NoSuchOwnedAssetClass
            );
            <Registry::<T>>::insert(id, rule_executor_address);
            Ok(())
        }

        /// A function callable by contracts
        /// which allows them to submit results of execution
        /// 
        /// * `origin`: The origin of a contract
        /// * `asset_id`: The id of the asset for which execution is submitted
        /// * `data_consumer_address`: The address of the caller of the contract
        /// * `data_consumer_ephemeral_pk`: A public key submitted by the data consumer. 
        ///                                 They will be able to decrypt the recovered cfrags using the
        ///                                 associated secret key.
        /// * `gateway`: The gateway node for which the command will be issued
        /// * `execution_result`: The result of the execute function as reported
        ///                       by the calling contract. A 'true' value implies
        ///                       access is granted, a 'false' implies it is not.
        /// TODO: Cleanup, break into smaller functions as needed
        /// leaving weight as 0 since otherwise contracts need to be funded
        #[pallet::weight(0)]
        pub fn submit_execution_results(
            origin: OriginFor<T>,
            #[pallet::compact] asset_id: T::AssetId,
            data_consumer_address: T::AccountId,
            execution_result: bool,
            data_consumer_ephemeral_pk: Vec<u8>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            // verify the caller is the registered rule executor contract
            match <Registry::<T>>::get(asset_id) {
                Some(addr) => {
                    ensure!(addr == who, Error::<T>::InvalidRuleExecutor);
                    // TODO: locks should expire after some number of blocks
                    // is there any way we can use the vesting schedule approach to facilitate this?
                    // needed? Probably not any longer
                    <Lock::<T>>::insert(&data_consumer_address, asset_id, execution_result);
                    if execution_result {
                        match <T as pallet::Config>::MetadataProvider::get(asset_id) {
                            Some(metadata) => {
                                // use the metadata to get the associated public key used to encrypt the data
                                <pallet_iris_proxy::Pallet<T>>::add_kfrag_request(
                                    data_consumer_address, 
                                    metadata.public_key,
                                    data_consumer_ephemeral_pk
                                );
                                Self::deposit_event(Event::ExecutionSuccess);
                            },
                            None => {
                                Self::deposit_event(Event::ExecutionFailed);
                                log::info!("No metadata found for asset id {:?}", asset_id);
                                return Ok(());
                            }
                        }
                    }
                },
                None => {
                    Self::deposit_event(Event::ExecutionFailed);
                    log::info!("No rule has registered for the asset id {:?}", asset_id);
                    return Ok(());
                }
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
        let opt_asset = <pallet_assets::Pallet<T>>::asset(id);
        match opt_asset {
            Some(owned) => owned.owner == who,
            None => false
        }
    }
}
