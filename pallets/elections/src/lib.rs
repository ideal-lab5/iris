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

//! # Elections Pallet
//!
//! @author driemworks
//! 
//! ## Description
//!
//! The elections pallet is responsible for executing and managing proxy node
//! elections.
//! 
//! 

#![cfg_attr(not(feature = "std"), no_std)]

mod mock;
mod tests;

use frame_support::{
	ensure,
	pallet_prelude::*,
	traits::{
		EstimateNextSessionRotation, Get,
		ValidatorSet, ValidatorSetWithIdentification,
	},
};
use log;
use scale_info::TypeInfo;
pub use pallet::*;
use sp_runtime::{
	SaturatedConversion,
	traits::{Convert, Zero}
};
use sp_staking::offence::{Offence, OffenceError, ReportOffence};
use sp_std::{
	collections::{btree_set::BTreeSet, btree_map::BTreeMap},
	str,
	vec::Vec,
	prelude::*
};
use sp_core::{
    offchain::{
        OpaqueMultiaddr, StorageKind,
    },
	crypto::KeyTypeId,
};
use frame_system::{
	self as system, 
	ensure_signed,
	offchain::{
		SendSignedTransaction,
		Signer,
	}
};
use sp_runtime::{
	offchain::http,
	traits::StaticLookup,
};

use iris_primitives::IngestionCommand;

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

	/// Configure the pallet by specifying the parameters and types on which it
	/// depends.
	/// TODO: reafactor? lots of tightly coupled pallets here, there must  
	/// be a better way to go about this
	#[pallet::config]
	pub trait Config: frame_system::Config + pallet_proxy::Config + pallet_ipfs::Config + pallet_data_assets::Config + pallet_authorities::Config
	{
		/// The Event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		/// the overarching call type
		type Call: From<Call<Self>>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);
	
	#[pallet::storage]
	#[pallet::getter(fn votes)]
	pub type Votes<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		Blake2_128Concat,
		T::AssetId,
		u128,
		ValueQuery,
	>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		ElectionError,
	}

	/*
	Note: Could use genesis state to approve initial, pre-defined transactions on network initialization
	*/

	// #[pallet::hooks]
	// impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
	// 	fn offchain_worker(block_number: T::BlockNumber) {
	// 		if <pallet_authorities::Pallet<T>>::do_run_election() {
	// 			// open election for N blocks
	// 			Self::run_proxy_node_election();
	// 			// after N blocks
	// 		}
	// 	}
	// }

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		// TODO: what are some constants that should be configurable by root node?
	}
}

impl<T: Config> Pallet<T> {
	// pub fn run_proxy_node_election(validators: Vec<T::AccountId>) -> Result<(), Error<T>> {
	// 	// get ipfs id by reading from ipfs pallet
	// 	let id_json = <pallet_ipfs::Pallet<T>>::fetch_identity_json().map_err(|_| Error::<T>::ElectionError).unwrap();
	// 	// get pubkey
	// 	let id = &id_json["ID"];
	// 	let pubkey = id.clone().as_str().unwrap().as_bytes().to_vec();
	// 	// get associated addr
	// 	match <pallet_ipfs::Pallet<T>>::substrate_ipfs_bridge(&pubkey) {
	// 		Some(addr) => {
	// 			if validators.contains(&addr) {
	// 				// get available storage in gb
	// 				let real_storage_size_gb = <pallet_ipfs::Pallet<T>>::stats(&addr);
	// 				// get active stake
	// 				let active_stake: <T as pallet_proxy::Config>::CurrencyBalance = <pallet_proxy::Pallet<T>>::ledger(&addr).unwrap().active;
	// 				let active_stake_primitive: u128 = active_stake.saturated_into::<u128>();
	// 				let mut ingestion_queue = <pallet_data_assets::Pallet<T>>::ingestion_queue();
	// 				Self::proxy_node_election(addr.clone(), real_storage_size_gb.clone(), active_stake_primitive.clone(), ingestion_queue);
	// 			} else {
	// 				log::info!("You are not a validator - not eligible for election participation.");
	// 			}
	// 		},
	// 		None => {
	// 			// do nothing
	// 		}
	// 	}
	// 	Ok(())
	// }

	// / A proxy places votes on ingestion commands
	// /
	// fn proxy_node_election(
	// 	proxy_addr: T::AccountId,
	// 	total_available_storage_gb: u128,
	// 	total_active_stake: u128,
	// 	mut ingestion_queue: Vec<IngestionCommand<T::AccountId, T::AssetId, Vec<u8>, T::Balance>>
	// ) {
	// 	let max_wait_time_for_50gb: u32 = 10;
	// 	// filter out items which are too large
	// 	let mut filtered_queue: Vec<IngestionCommand<T::AccountId, T::AssetId, Vec<u8>, T::Balance>> =
	// 		ingestion_queue.into_iter()
	// 			.filter(|i| i.estimated_size_gb < total_available_storage_gb)
	// 			.collect();
	// 	// sort by balance
	// 	filtered_queue.sort_by(|a, b| a.balance.cmp(&b.balance));
	// 	// Choose top k results s.t. max storage needed doesn't exceed total storage available
	// 	let mut total_gb: u128 = 0u128;
	// 	let mut candidate_commands: Vec<IngestionCommand<
	// 		T::AccountId, T::AssetId, Vec<u8>, T::Balance,
	// 	>> = Vec::new();
	// 	for f in filtered_queue.into_iter() {
	// 		let balance: T::Balance = f.balance;
	// 		let balance_primitive = TryInto::<u128>::try_into(balance).ok().unwrap();
	// 		total_gb = total_gb + balance_primitive;
	// 		if total_gb < total_available_storage_gb {
	// 			candidate_commands.push(f);
	// 		} else {
	// 			break
	// 		}
	// 	}
	// 	let weight_per_gb = total_active_stake / total_gb;
	// 	for c in candidate_commands.into_iter() {
	// 		let weight: u128 = weight_per_gb * c.estimated_size_gb;
	// 		// place your weighted vote
	// 		<Votes<T>>::insert(proxy_addr.clone(), c.asset_id, weight);
	// 	}
	// }
}	
