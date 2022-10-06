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

use sp_runtime::traits::{Convert, StaticLookup};
use sp_std::{
    prelude::*,
};
use frame_support::traits::{ValidatorSet, ValidatorSetWithIdentification};

use core::convert::TryInto;

use frame_system::ensure_signed;
use pallet_data_assets::{MetadataProvider, QueueProvider};

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
	pub trait Config: frame_system::Config + pallet_assets::Config + pallet_authorities::Config {
        /// The overarching event type
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        /// the overarching call type
	    type Call: From<Call<Self>>;
        /// A type for retrieving the validators supposed to be online in a session.
		type ValidatorSet: ValidatorSetWithIdentification<Self::AccountId>;
        /// provide queued requests to vote on
		type QueueProvider: pallet_data_assets::QueueProvider<Self::AccountId, Self::AssetId, Self::Balance>;
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

    // #[pallet::storage]
    // pub type EjectionCommands<T: Config> = StorageMap<
    //     _,
    //     Blake2_128Concat,
    //     T::AccountId,
    //     Vec<EjectionCommand<T::AccountId, T::AssetId>>,
    //     ValueQuery,
    // >;

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
            data_consumer_ephemeral_pk: Vec<u8>,
            gateway: T::AccountId,
            execution_result: bool,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            // verify that the data_consumer holds an asset from the asset class
            // TODO: REVISIT THIS CONCEPTUALLY
            // let balance = <pallet_assets::Pallet<T>>::balance(asset_id.clone(), data_consumer_address.clone());
            // let balance_primitive = TryInto::<u64>::try_into(balance).ok();
            // this check is potentially going to go away in the near future
            // as we may no longer enforce that you need to own an asset id to access the data
            // (instead asset ownership implies partial ownership, rewards, providing availability, etc)
            match <pallet_assets::Pallet<T>>::asset(asset_id.clone()) {
                Some(asset) => {
                    // TODO: REVISIT THIS
                    // match balance_primitive {
                    //     Some(b) => ensure!(balance >= asset.min_balance, Error::<T>::InsufficientBalance),
                    //     None => {
                    //         return Ok(());
                    //     }
                    // }
                    // verify the caller is the registered rule executor contract
                    match <Registry::<T>>::get(asset_id.clone()) {
                        Some(addr) => {
                            ensure!(addr == who.clone(), Error::<T>::InvalidRuleExecutor);
                            // TODO: locks should expire after some number of blocks
                            // is there any way we can use the vesting schedule approach to facilitate this?
                            <Lock::<T>>::insert(&data_consumer_address, &asset_id, execution_result);
                            if execution_result {
                                match T::MetadataProvider::get(asset_id.clone()) {
                                    Some(metadata) => {
                                        // Do I need this 'fragment owners'? is there some other way I can do this>
                                        let frag_holders = T::QueueProvider::get_fragment_holders(metadata.public_key.clone());
                                        // here we make the assumption that validators do not go offline during the duration of a session
                                        // this could be made more precise by relying on the heartbeat delivered via imonline
                                        let validators = <pallet_authorities::Pallet<T>>::validators();
                                        // we only need to find 'threshold' fragment holders
                                        for f in frag_holders.iter() {
                                            // if in validators set, we assume the node is active and can process the request
                                            if validators.contains(f) {
                                                T::QueueProvider::add_capsule_recovery_request(
                                                    data_consumer_address.clone(),
                                                    asset_id.clone(),
                                                    f, metadata.public_key.clone(), data_consumer_ephemeral_pk.clone(),
                                                );
                                                // TODO: need to stop after we have selected 'threshold' validators
                                            }
                                        }
                                    },
                                    None => { return Ok(()) }
                                }
                            }
                        },
                        None => { return Ok(()) }
                    }
                },
                None => {},
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
