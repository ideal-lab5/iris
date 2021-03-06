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

//! # Data Space Pallet
//!
//! ## Overview
//!
//! ### Goals
//! The Data Space module provides functionality for creation and management of data spaces and data space accessibility
//! 
//! ### Dispatchable Functions 
//!
//! #### Permissionless functions
//! * create
//!
//! #### Permissioned Functions
//! * mint
//! * associate_asset_class_with_data_space
//!

use scale_info::TypeInfo;
use codec::{Encode, Decode};
use frame_support::{
    traits::ReservableCurrency,
};

use log;

use sp_runtime::{
    RuntimeDebug,
    traits::StaticLookup,
    transaction_validity::{ ValidTransaction, TransactionValidity },
};
use sp_std::{
    prelude::*,
};

use pallet_iris_assets::{
	DataCommand,
};

use frame_system::{
	self as system, 
	ensure_signed,
	offchain::{
		SendSignedTransaction,
		Signer,
	}
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

pub mod crypto {
	// use crate::KEY_TYPE;
	use sp_core::crypto::KeyTypeId;
	use sp_core::sr25519::Signature as Sr25519Signature;
	use sp_runtime::app_crypto::{app_crypto, sr25519};
	use sp_runtime::{traits::Verify, MultiSignature, MultiSigner};
	use sp_std::convert::TryFrom;

	pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

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
                    pallet_iris_assets::Config {
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
	}

    #[pallet::validate_unsigned]
	impl<T: Config> ValidateUnsigned for Pallet<T> {
		type Call = Call<T>;
		/// Validate unsigned call to this module.
		fn validate_unsigned(_source: TransactionSource, call: &Self::Call) -> TransactionValidity {
            if let Call::associate_asset_class_with_data_space{
                dataspace_id,
                asset_class_id,
            } = call {
                log::info!("Signature is valid");
                return ValidTransaction::with_tag_prefix("iris")
                    .priority(100)
                    .longevity(5)
                    .propagate(true)
                    .build();
			} else {
				InvalidTransaction::Call.into()
			}
		}
	}

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(block_number: T::BlockNumber) {
            if let Err(e) = Self::submit_unsigned_tx_associate_data_space_asset_class(block_number) {
                log::error!("DataSpaces: Encountered an error when processing dataspace inclusion request: {:?}", e);
            }
		}
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
        #[pallet::weight(0)]
        pub fn associate_asset_class_with_data_space(
            origin: OriginFor<T>,
            dataspace_id: T::AssetId,
            asset_class_id: T::AssetId,
            // dataspace_assoc_req: DataSpaceAssociationRequest<T::AssetId>,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            // this is obviously insecure right now
            // will address this when we build the proxy routing service in milestone 2
            // TODO: verify asset class exists
            // TODO: should verify that the asset class has the dataspace id set as a pending association
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

    /// A helper function to (futuristically) perform moderation tasks,
    ///  sign payload and send an unsigned transaction
	fn submit_unsigned_tx_associate_data_space_asset_class(
		_block_number: T::BlockNumber,
	) -> Result<(), &'static str> {
        // in the future, this is where moderation capabilities will hook in
        let data_queue = <pallet_iris_assets::Pallet<T>>::data_space_request_queue();
        let len = data_queue.len();
        if len != 0 {
            log::info!("DataSpaces: {} entr{} in the data queue", len, if len == 1 { "y" } else { "ies" });
        }
        for cmd in data_queue.into_iter() {
            match cmd {
                // doing this in an offchain context to prepare for next stage
                // where a moderator node will verify if the data 
                // is eligible for inclusion into the data spaces
                DataCommand::AddToDataSpace(id, dataspace_id) => {
                    log::info!("Processing add to data space command");
                    if sp_io::offchain::is_validator() {
                        log::info!("Attempting to send unsigned transaction from validator node");
                        // if you are a validator, attempt to add to dataspace
                        // in the future this will be replaced with a moderator node
                        // and we select the moderator using a routing service
                        let signer = Signer::<T, T::AuthorityId>::all_accounts();
                        if !signer.can_sign() {
                            log::error!(
                                "No local accounts available. Consider adding one via `author_insertKey` RPC.",
                            );
                        }
                        let results = signer.send_signed_transaction(|_account| { 
                            Call::associate_asset_class_with_data_space{
                                asset_class_id: id.clone(),
                                dataspace_id: dataspace_id.clone(),
                            }
                        });
                
                        for (_, res) in &results {
                            match res {
                                Ok(()) => log::info!("Submitted ipfs results"),
                                Err(e) => log::error!("Failed to submit transaction: {:?}",  e),
                            }
                        }
                    }
                },
                _ => {
                    // ignore others
                }
            }
        }

		Ok(())
	}
}