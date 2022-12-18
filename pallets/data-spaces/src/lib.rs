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

use scale_info::TypeInfo;
use codec::{Encode, Decode};
use frame_support::{
    traits::ReservableCurrency,
};

use sp_runtime::{
    RuntimeDebug,
    traits::StaticLookup,
};
use sp_std::{
    prelude::*,
};
use frame_system::{
	self as system, 
	ensure_signed,
};

pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

/// the metadata for a data space
#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub struct DataSpaceMetadata<AssetId> {
    /// the name of the data space
    name: Vec<u8>,
    /// ids of asset classes included in the data space
    asset_ids: Vec<AssetId>,
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
	use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
	use frame_system::{
        pallet_prelude::*,
        offchain::{
            AppCrypto,
            CreateSignedTransaction,
        },
    };
	use sp_std::{
        str,
    };

	#[pallet::config]
    /// the module configuration trait
	pub trait Config: CreateSignedTransaction<Call<Self>> + 
                    frame_system::Config + 
                    pallet_assets::Config + 
                    pallet_data_assets::Config {
        /// The overarching event type
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        /// the overarching call type
	    type Call: From<Call<Self>>;
        /// the currency used
        type Currency: ReservableCurrency<Self::AccountId>;
        /// the authority id used for signing txs
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
    #[pallet::without_storage_info]
	pub struct Pallet<T>(_);

    // map dataspace id to dataspace metadata
    #[pallet::storage]
    #[pallet::getter(fn metadata)]
    pub(super) type Metadata<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AssetId,
        DataSpaceMetadata<T::AssetId>,
    >;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
        DataSpaceCreationSuccess(T::AccountId, T::AssetId),
        DataSpaceAssetCreationSuccess(T::AccountId, T::AssetId),
        DataSpaceAssociationSuccess(T::AssetId, T::AssetId),
	}

	#[pallet::error]
	pub enum Error<T> {
        CantCreateAssetClass,
        CantMintAssets,
        DataSpaceNotAccessible,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {

        /// Create a new (private) named data space
        #[pallet::weight(100)]
        pub fn create(
            origin: OriginFor<T>,
            admin: <T::Lookup as StaticLookup>::Source,
            name: Vec<u8>,
            #[pallet::compact] id: T::AssetId,
            #[pallet::compact] balance: T::Balance,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let new_origin = system::RawOrigin::Signed(who.clone()).into();
            <pallet_assets::Pallet<T>>::create(
                new_origin, id.clone(), admin.clone(), balance
            ).map_err(|_| Error::<T>::CantCreateAssetClass)?;
            // associate asset id with name
            <Metadata<T>>::insert(id.clone(), DataSpaceMetadata { 
                name: name.clone(),
                asset_ids: Vec::new(),
            });
            Self::deposit_event(Event::DataSpaceCreationSuccess(who.clone(), id.clone()));
			Ok(())
        }

        /// Create access tokens for a data space
        #[pallet::weight(100)]
        pub fn mint(
            origin: OriginFor<T>,
            beneficiary: <T::Lookup as StaticLookup>::Source,
            #[pallet::compact] asset_id: T::AssetId,
            #[pallet::compact] amount: T::Balance,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            let new_origin = system::RawOrigin::Signed(who.clone()).into();
            let beneficiary_accountid = T::Lookup::lookup(beneficiary.clone())?;
            <pallet_assets::Pallet<T>>::mint(
                new_origin, 
                asset_id.clone(), 
                beneficiary.clone(), 
                amount
            ).map_err(|_| Error::<T>::CantMintAssets)?;
        
            Self::deposit_event(Event::DataSpaceAssetCreationSuccess(
                beneficiary_accountid.clone(), asset_id.clone()
            ));
            Ok(())
        }

        /// associate an asset class with a set of data spaces
        /// We still need to secure this to make it callable only by offchain workers
        #[pallet::weight(100)]
        pub fn bond(
            origin: OriginFor<T>,
            dataspace_id: T::AssetId,
            asset_class_id: T::AssetId,
            // dataspace_assoc_req: DataSpaceAssociationRequest<T::AssetId>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            // check that the caller has dataspace access
            let balance = <pallet_assets::Pallet<T>>::balance(dataspace_id.clone(), who.clone());
            let balance_primitive = TryInto::<u128>::try_into(balance).ok();
            ensure!(balance_primitive != Some(0), Error::<T>::DataSpaceNotAccessible);
            let mut metadata = <Metadata::<T>>::get(dataspace_id.clone()).unwrap();
            //  duplicate avoidance 
            if !metadata.asset_ids.contains(&asset_class_id.clone()) {
                metadata.asset_ids.push(asset_class_id.clone());
                <Metadata<T>>::insert(dataspace_id.clone(), metadata);
                Self::deposit_event(Event::DataSpaceAssociationSuccess(
                    dataspace_id.clone(), asset_class_id.clone()
                ));
            }
            
            Ok(())
        }
	}
}

impl<T: Config> Pallet<T> {

}