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

use codec::HasCompact;
use frame_support::{
	ensure,
	pallet_prelude::*,
	traits::{
		EstimateNextSessionRotation, Get,
		ValidatorSet, ValidatorSetWithIdentification,
	},
};
// use log;
use scale_info::TypeInfo;
pub use pallet::*;
use sp_runtime::{
	SaturatedConversion,
	traits::{AtLeast32BitUnsigned, Convert, Zero}
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

use pallet_data_assets::QueueProvider;
use pallet_proxy::ProxyProvider;
use iris_primitives::IngestionCommand;

pub const LOG_TARGET: &'static str = "runtime:elections";

// syntactic sugar for logging.
#[macro_export]
macro_rules! log {
	($level:tt, $patter:expr $(, $values:expr)* $(,)?) => {
		log::$level!(
			target: crate::LOG_TARGET,
			concat!("[{:?}] 🗳 ", $patter), <frame_system::Pallet<T>>::block_number() $(, $values)*
		)
	};
}

pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

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

/// The vote to track weighted votes
#[derive(PartialEq, Eq, Clone, Encode, Decode, RuntimeDebug, TypeInfo)]
pub struct Vote<AccountId, Balance> {
	/// the weight of the voter
	pub weight: Balance,
	/// the voter
	pub voter: AccountId,
}

/// stores information about the election winners and if they have executed the command
#[derive(PartialEq, Eq, Clone, Encode, Decode, RuntimeDebug, TypeInfo)]
pub struct CommandExecution<AccountId> {
	/// the account id of the winner
	pub account: AccountId,
	/// the status to check if the account submitted proof of execution
	pub execution_status: bool,
}

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

	#[pallet::config]
	pub trait Config: CreateSignedTransaction<Call<Self>> + frame_system::Config
	{
		/// The Event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		/// the overarching call type
		type Call: From<Call<Self>>;
		/// the authority id used for sending signed txs
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;
		/// The units in which we record balances.
		type Balance: Member
		+ Parameter
		+ AtLeast32BitUnsigned
		+ Default
		+ Copy
		+ MaybeSerializeDeserialize
		+ MaxEncodedLen
		+ TypeInfo;
		/// Identifier for the class of asset.
		type AssetId: Member
			+ Parameter
			+ Default
			+ Copy
			+ HasCompact
			+ MaybeSerializeDeserialize
			+ MaxEncodedLen
			+ TypeInfo;
		/// provide queued requests to vote on
		type QueueProvider: pallet_data_assets::QueueProvider<Self::AccountId, Self::AssetId, Self::Balance>;
		type ProxyProvider: pallet_proxy::ProxyProvider<Self::AccountId, Self::Balance>;
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);
	
	///  a map of data owner to CID to redistributed stake
	#[pallet::storage]
	pub type WeightedVote<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		Blake2_128Concat,
		Vec<u8>,
		Vec<Vote<T::AccountId, T::Balance>>,
		OptionQuery,
	>;

	/// ingestion requests that are currently being voted on
	#[pallet::storage]
	pub type Pending<T: Config> = StorageValue<
		_, Vec<IngestionCommand<T::AccountId, T::AssetId, T::Balance>>, ValueQuery
	>;

	/// ingestion requests that are currently ready for processing
	#[pallet::storage]
	pub type Active<T: Config> = StorageValue<
		_, Vec<IngestionCommand<T::AccountId, T::AssetId, T::Balance>>, ValueQuery
	>;

	/// map (owner -> cid) -> (election winners, execution status)
	/// TODO: this will be important when we actually reward the gateway nodes
	/// we need to make sure they have actually submitted results
	#[pallet::storage]
	pub type Nominees<T: Config> = StorageDoubleMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		Blake2_128Concat,
		Vec<u8>,
		Vec<T::AccountId>,
		ValueQuery,
	>;

	#[pallet::storage]
	pub type CommandExecutionResults<T: Config> = StorageNMap<
		_,
		(storage::Key<Blake2_128Concat, T::AccountId>,
		storage::Key<Blake2_128Concat, Vec<u8>>,
		storage::Key<Blake2_128Concat, T::AccountId>),
		bool,
		OptionQuery,
	>;

	#[pallet::storage]
	pub type StakeRestributionInterval<T: Config> = StorageValue<_, u32, ValueQuery>;

	#[pallet::storage]
	pub type ElectionInterval<T: Config> = StorageValue<_, u32, ValueQuery>;

	#[pallet::storage]
	pub type ExecutionResultInterval<T: Config> = StorageValue<_, u32, ValueQuery>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		QueueLocked,
		VoteRecorded,
	}

	#[pallet::error]
	pub enum Error<T> {
		NotProxy,
		ElectionError,
		RequestDoesNotExist,
		InsufficientBond,
	}

	#[pallet::genesis_config]
	pub struct GenesisConfig {
		pub stake_redistribution_interval: u32,
		pub election_interval: u32,
		pub execution_result_interval: u32,
	}

	#[cfg(feature = "std")]
	impl Default for GenesisConfig {
		fn default() -> Self {
			GenesisConfig {
				// should at least be coprime
				stake_redistribution_interval: 7,
				election_interval: 11,
				execution_result_interval: 17,
			}
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig {
		fn build(&self) {
			StakeRestributionInterval::<T>::put(self.stake_redistribution_interval);
			ElectionInterval::<T>::put(self.election_interval);
			ExecutionResultInterval::<T>::put(self.execution_result_interval);
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(block_number: T::BlockNumber) {
			if block_number % <ElectionInterval::<T>>::get().into() == 0u32.into() {
				Self::lock_queue();
			}
			// wait X blocks until voting/stake redistribution if finalized
			if block_number % <StakeRestributionInterval::<T>>::get().into() == 0u32.into() {
				// now we report the results to the ipfs pallet
				Self::tally_and_report_results();
			}
			if block_number % ExecutionResultInterval::<T>::get().into() == 0u32.into() {
				// cleanup activities => reward + slashes
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {

		// TODO: should this take blocknumber as a parameter?
		#[pallet::weight(100)]
		pub fn lock_ingestion_queue(
			origin: OriginFor<T>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			// should have strict conditions that allow this execution to happen
			// - expected blocknumber
			// - can only be executed once 
			match T::ProxyProvider::bonded(who.clone()) {
				Some(proxy) => {
					let mut queue_clone = T::QueueProvider::ingestion_queue().clone();
					T::QueueProvider::kill_ingestion_queue();
					Pending::<T>::mutate(|a| {
						a.append(&mut queue_clone)
					});
					// emit event
					return Ok(());
				},
				// emit event or error
				None => Ok(())
			}
		}

		/// * `results`: A map between index in active requests queue and the winners this node is proposing
		#[pallet::weight(100)]
		pub fn close_election(
			origin: OriginFor<T>,
			results: BTreeMap<u32, Vec<T::AccountId>>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			// TODO: need similar validations as lock queue extrinsic
			match T::ProxyProvider::bonded(who.clone()) {
				Some(proxy) => {
					let mut no_votes = Vec::new();
					for (pos, a) in Pending::<T>::get().into_iter().enumerate() {
						let p = pos as u32;
						match results.get(&p) {
							Some(winners) => {

								// let mut nominees: Vec<Nominee<T::AccountId>> = Vec::new();
								// for w in winners.iter() {
								// 	nominees.push(Nominee{
								// 		account: w.clone(),
								// 		execution_status: false,
								// 	});
								// }	
									
								Nominees::<T>::insert(
									a.owner.clone(), 
									a.cid.clone(), 
									winners,
								);
								Active::<T>::mutate(|active| {active.push(a)})
							},
							None => {
								no_votes.push(a);
							}
						};
					}
					// set active to only contains elements with no votes
					// wait.. this isn't quite right...
					Pending::<T>::kill();
					Pending::<T>::mutate(|pending| {
						pending.append(&mut no_votes)
					});
					// emit event
					return Ok(());
				},
				// emit event or error?
				None => Ok(())
			}
			
		}

		///
		/// * `distribution`: The distribution of balance to ingestion queue item, 
		///					  as identified by its index in the active queue. It maps
		///					  the index of the ingestion request to a percentage of your stake.
		///					  Total cannot exceed 100%
		///
		#[pallet::weight(100)]
		pub fn redistribute_stake(
			origin: OriginFor<T>,
			index: u32,
			amount: T::Balance
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
			Self::do_redistribute_stake(who, index, amount)?;
			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	fn lock_queue() {
		// after collecting all votes, submit results on chain
		let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			log::error!(
				"No local accounts available. Consider adding one via `author_insertKey` RPC.",
			);
		}
		let results = signer.send_signed_transaction(|_account| { 
			Call::lock_ingestion_queue{ }
		});

		for (_, res) in &results {
			match res {
				Ok(()) => log::info!("Submitted results successfully"),
				Err(e) => log::error!("Failed to submit transaction: {:?}",  e),
			}
		}
	}

	/// Iterate over votes and choose set of accounts who placed the highest stake
	pub fn choose_winners(mut votes: Vec<Vote<T::AccountId, T::Balance>>) -> Vec<T::AccountId> {
		let mut winners = Vec::new();
		// sort votes by decreasing weight
		votes.sort_by(|u, v| u.weight.cmp(&v.weight));
		// get max weight
		let max_weight = votes[0].weight;
		// get all votes with max_weight
		let votes = votes.into_iter().filter(|v| v.weight == max_weight);
		let mut candidates: Vec<T::AccountId> = votes.map(|vote| vote.voter).collect();
		winners.append(&mut candidates);
		winners
	}

	// after N blocks, we mark the 'stake redistribution phase' as over
	// when it is over, we destroy the active queue and report the winners to the ipfs pallet
	fn tally_and_report_results() {
		// for each element of the active queue
		let pending = <Pending<T>>::get();
		let mut election_results = BTreeMap::new();
		let num_pending = pending.len();
		log::info!("Processing {:?} active requests", num_pending);
		// since active is an ordered list, we don't need to store the entire command in the hashmap
		// we only need to store the index
		for (pos, p) in pending.iter().enumerate() {
			// get the weighted votes
			match <WeightedVote<T>>::get(p.owner.clone(), p.cid.clone()) {
				Some(votes) => {
					let winners = Self::choose_winners(votes);
					WeightedVote::<T>::remove(p.owner.clone(), p.cid.clone());
					election_results.insert(pos as u32, winners);
				},
				None => {
					log::info!("No votes were places for this item with cid = {:?} and owner = {:?}", p.cid, p.owner);
				}
			}
		}

		// after collecting all votes, submit results on chain
		let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
		if !signer.can_sign() {
			log::error!(
				"No local accounts available. Consider adding one via `author_insertKey` RPC.",
			);
		}
		let results = signer.send_signed_transaction(|_account| { 
			Call::close_election{
				results: election_results.clone(),
			}
		});

		for (_, res) in &results {
			match res {
				Ok(()) => log::info!("Submitted results successfully"),
				Err(e) => log::error!("Failed to submit transaction: {:?}",  e),
			}
		}
	}

	/// Allocate a portion of active stake to a reserved pool and associate it with some
	/// ingestion request in the Active queue.
	/// 
	/// * `voter`: The node for which stake should be reserved
	/// * `index`: The index in the Active storage map of the ingestion request to specify
	/// * `amount`: The amount of active stake to move to reserved
	///
	fn do_redistribute_stake(
		voter: T::AccountId,
		index: u32,
		amount: T::Balance,
	) -> Result<(), Error<T>> {
		// we need to make sure that the total percentage doesn't exceed 100
		let pending = Pending::<T>::get();
		let len = pending.len();
		// if there are no active, then do nothing
		if len == 0 {
			return Ok(());
		}
		let is_len_too_big = usize::try_from(index)
			.map(|index| len > index)
			.unwrap_or(false);
		ensure!(is_len_too_big, Error::<T>::RequestDoesNotExist);
		let voter_active_stake = T::ProxyProvider::active(voter.clone()).unwrap_or(Zero::zero());
		ensure!(voter_active_stake > Zero::zero(), Error::<T>::InsufficientBond);
		T::ProxyProvider::reserve(voter.clone(), amount.clone());
		let req = &pending[index as usize];
		let vote = Vote {
			weight: amount,
			voter: voter.clone(),
		}; 
		let mut votes = WeightedVote::<T>::get(req.owner.clone(), req.cid.clone()).unwrap_or(Vec::new());
		votes.push(vote);
		WeightedVote::<T>::insert(req.owner.clone(), req.cid.clone(), votes.clone());
		Ok(())
	}
}	

/// a trait to share election information with other modules
pub trait ElectionProvider<AccountId, AssetId, Balance> {
	/// returns the collection of active commands
	fn active() -> Vec<IngestionCommand<AccountId, AssetId, Balance>>;
	/// returns the election winners nominated to process the command
	fn nominees(owner: AccountId, cid: Vec<u8>) -> Vec<AccountId>;
	// report that an assigned command has been completed
	fn report_execution(assignee: AccountId, owner: AccountId, cid: Vec<u8>);
}

impl<T: Config> ElectionProvider<T::AccountId, T::AssetId, T::Balance> for Pallet<T> {
	fn active() -> Vec<IngestionCommand<T::AccountId, T::AssetId, T::Balance>> {
		Active::<T>::get()
	}

	fn nominees(owner: T::AccountId, cid: Vec<u8>) -> Vec<T::AccountId> {
		Nominees::<T>::get(owner, cid)
	}

	fn report_execution(assignee: T::AccountId, owner: T::AccountId, cid: Vec<u8>) {
		// verify that the item is assigned to the assignee
		if Nominees::<T>::get(owner, cid).contains(&assignee) {
			// CommandExecutionResults
		}
	}

}
