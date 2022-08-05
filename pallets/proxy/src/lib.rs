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

//! # Proxy Pallet
//!
//! @author driemworks
//! 
//! ## Description 
//!
//! The pallet uses the Session pallet and implements related traits for session
//! management. Currently it uses periodic session rotation provided by the
//! session pallet to automatically rotate sessions. For this reason, the
//! proxy addition and removal becomes effective only after 2 sessions
//! (queuing + applying).
//! 
//! 

#![cfg_attr(not(feature = "std"), no_std)]

mod mock;
mod tests;

use frame_support::{
	ensure, parameter_types,
	pallet_prelude::*,
	traits::{
		EstimateNextSessionRotation, Get, Currency, LockableCurrency,
		DefensiveSaturating, LockIdentifier, WithdrawReasons,
	},
	BoundedVec,
};
use scale_info::TypeInfo;
pub use pallet::*;
use sp_runtime::{
	SaturatedConversion,
	traits::{CheckedSub, Convert, Zero, Verify},
};
use sp_staking::offence::{Offence, OffenceError, ReportOffence};
use sp_std::{
	collections::btree_map::BTreeMap,
	str,
	prelude::*
};
use sp_core::{
    offchain::{
        OpaqueMultiaddr, StorageKind,
    },
	crypto::KeyTypeId,
	sr25519::{Signature, Public},
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
use codec::HasCompact;
use iris_primitives::IngestionCommand;
use pallet_authorities::EraProvider;
use pallet_data_assets::QueueProvider;

pub const LOG_TARGET: &'static str = "runtime::proxy";
// TODO: should a new KeyTypeId be defined? e.g. b"iris"
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

// syntactic sugar for logging.
#[macro_export]
macro_rules! log {
	($level:tt, $patter:expr $(, $values:expr)* $(,)?) => {
		log::$level!(
			target: crate::LOG_TARGET,
			concat!("[{:?}] 💸 ", $patter), <frame_system::Pallet<T>>::block_number() $(, $values)*
		)
	};
}

const STAKING_ID: LockIdentifier = *b"staking ";

type BalanceOf<T> =
	<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;
/// Counter for the number of eras that have passed.

pub type EraIndex = u32;
/// counter for the number of "reward" points earned by a given storage provider
pub type RewardPoint = u32;


parameter_types! {
	pub MaxUnlockingChunks: u32 = 32;
}

/// Just a Balance/BlockNumber tuple to encode when a chunk of funds will be unlocked.
#[derive(PartialEq, Eq, Clone, Encode, Decode, RuntimeDebug, TypeInfo)]
pub struct UnlockChunk<Balance: HasCompact> {
	/// Amount of funds to be unlocked.
	#[codec(compact)]
	value: Balance,
	/// Era number at which point it'll be unlocked.
	#[codec(compact)]
	era: EraIndex,
}

/// The ledger of a (bonded) stash.
#[derive(PartialEq, Eq, Clone, Encode, Decode, RuntimeDebug, TypeInfo)]
#[scale_info(skip_type_params(T))]
pub struct StakingLedger<T: Config> {
	/// The stash account whose balance is actually locked and at stake.
	pub stash: T::AccountId,
	/// The total amount of the stash's balance that we are currently accounting for.
	/// It's just `active` plus all the `unlocking` balances.
	#[codec(compact)]
	pub total: BalanceOf<T>,
	/// The total amount of the stash's balance that will be at stake in any forthcoming
	/// rounds.
	#[codec(compact)]
	pub active: BalanceOf<T>,
	/// Any balance that is becoming free, which may eventually be transferred out of the stash
	/// (assuming it doesn't get slashed first). It is assumed that this will be treated as a first
	/// in, first out queue where the new (higher value) eras get pushed on the back.
	pub unlocking: BoundedVec<UnlockChunk<BalanceOf<T>>, MaxUnlockingChunks>,
	// / List of eras for which the stakers behind a validator have claimed rewards. Only updated
	// / for validators.
	// pub claimed_rewards: Vec<EraIndex>,
}

/// The vote to track weighted votes
#[derive(PartialEq, Eq, Clone, Encode, Decode, RuntimeDebug, TypeInfo)]
pub struct Vote<AccountId> {
	/// the weight of the voter
	pub weight: u128,
	/// the voter
	pub voter: AccountId,
}

impl<T: Config> StakingLedger<T> {
	/// Initializes the default object using the given `validator`.
	pub fn default_from(stash: T::AccountId) -> Self {
		Self {
			stash,
			total: Zero::zero(),
			active: Zero::zero(),
			unlocking: Default::default(),
		}
	}


	/// Re-bond funds that were scheduled for unlocking.
	///
	/// Returns the updated ledger, and the amount actually rebonded.
	fn rebond(mut self, value: BalanceOf<T>) -> (Self, BalanceOf<T>) {
		let mut unlocking_balance = BalanceOf::<T>::zero();

		while let Some(last) = self.unlocking.last_mut() {
			if unlocking_balance + last.value <= value {
				unlocking_balance += last.value;
				self.active += last.value;
				self.unlocking.pop();
			} else {
				let diff = value - unlocking_balance;

				unlocking_balance += diff;
				self.active += diff;
				last.value -= diff;
			}

			if unlocking_balance >= value {
				break
			}
		}

		(self, unlocking_balance)
	}
}

/// Indicates the initial status of the staker.
#[derive(RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize, Clone))]
pub enum ProxyStatus {
	/// Chilling.
	Idle,
	/// Declared desire in participating as an active proxy
	Proxy,
	/// The proxy node is misconfigured and requires attention (e.g. no IPFS daemon is detected)
	Invalid,
}

/// preferences for a proxy node
#[derive(PartialEq, Eq, Clone, Encode, Decode, RuntimeDebug, TypeInfo, Default)]
pub struct ProxyPrefs {
	pub max_mbps: u32,
	pub storage_max_gb: u128,
}

/// Indicates the configuration phase of the proxy node
#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub enum ProxyConfigState {
	Unconfigured,
	Identified,
	FullyConfigured,
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

	/// Configure the pallet by specifying the parameters and types on which it
	/// depends.
	/// TODO: probably don't need to tightly coupole the data assets pallet
	#[pallet::config]
	pub trait Config: frame_system::Config + 
					  pallet_data_assets::Config +
					  pallet_ipfs::Config +
					  pallet_authorities::Config
	{
		/// The Event type.
		type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
		/// the overarching call type
		type Call: From<Call<Self>>;
		/// the currency used by the pallet
		// type Currency: ReservableCurrency<Self::AccountId>;
		/// The staking balance.
		type Currency: LockableCurrency<
			Self::AccountId,
			Moment = Self::BlockNumber,
			Balance = Self::CurrencyBalance,
		>;
		/// Just the `Currency::Balance` type; we have this item to allow us to constrain it to
		/// `From<u64>`.
		type CurrencyBalance: sp_runtime::traits::AtLeast32BitUnsigned
			+ codec::FullCodec
			+ Copy
			+ MaybeSerializeDeserialize
			+ sp_std::fmt::Debug
			+ Default
			+ From<u64>
			+ TypeInfo
			+ MaxEncodedLen;
		type QueueProvider: pallet_data_assets::QueueProvider<Self::AccountId, Self::Balance>;
		type EraProvider: pallet_authorities::EraProvider;
		/// Number of eras that staked funds must remain bonded for.
		#[pallet::constant]
		type BondingDuration: Get<EraIndex>;
	}

	#[pallet::type_value]
	pub(crate) fn HistoryDepthOnEmpty() -> u32 {
		84u32
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	/// The map from (wannabe) validator stash key to the preferences of that validator.
	#[pallet::storage]
	#[pallet::getter(fn proxies)]
	pub type Proxies<T: Config> =
		CountedStorageMap<_, Twox64Concat, T::AccountId, ProxyPrefs>;

	/// Track which proxy nodes require configuration and identity verification
	/// If an address is mapped to true, then it requires configuration
	/// If it is mapped to false, then it is already configured
	///
	#[pallet::storage]
	#[pallet::getter(fn proxy_config_status)]
	pub type ProxyConfigStatus<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, ProxyConfigState>;

	/// The minimum active bond to become and maintain the role of a nominator.
	#[pallet::storage]
	pub type MinProxyBond<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

	/// The maximum proxy count before we stop allowing new proxies to join.
	///
	/// When this value is not set, no limits are enforced.
	#[pallet::storage]
	pub type MaxProxyCount<T> = StorageValue<_, u32, OptionQuery>;

	/// Map from all locked "stash" accounts to the controller account.
	#[pallet::storage]
	#[pallet::getter(fn bonded)]
	pub type Bonded<T: Config> = StorageMap<_, Twox64Concat, T::AccountId, T::AccountId>;
	
	/// Map from all (unlocked) "controller" accounts to the info regarding the staking.
	#[pallet::storage]
	#[pallet::getter(fn ledger)]
	pub type Ledger<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, StakingLedger<T>>;
		
	#[pallet::storage]
	pub type WeightedVote<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		IngestionCommand<T::AccountId, T::Balance>,
		Vec<Vote<T::AccountId>>,
		OptionQuery,
	>;

	#[pallet::storage]
	pub type StakeRestributionInterval<T: Config> = StorageValue<_, u32, ValueQuery>;

	#[pallet::storage]
	pub type ElectionInterval<T: Config> = StorageValue<_, u32, ValueQuery>;

	/// Number of eras to keep in history.
	///
	/// Information is kept for eras in `[current_era - history_depth; current_era]`.
	///
	/// Must be more than the number of eras delayed by session otherwise. I.e. active era must
	/// always be in history. I.e. `active_era > current_era - history_depth` must be
	/// guaranteed.
	// #[pallet::storage]
	// #[pallet::getter(fn history_depth)]
	// pub(crate) type HistoryDepth<T> = StorageValue<_, u32, ValueQuery, HistoryDepthOnEmpty>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// An account has bonded this amount. \[stash, amount\]
		///
		/// NOTE: This event is only emitted when funds are bonded via a dispatchable. Notably,
		/// it will not be emitted for staking rewards when they are added to stake.
		Bonded(T::AccountId, BalanceOf<T>),
		/// An account has unbonded this amount. \[stash, amount\]
		Unbonded(T::AccountId, BalanceOf<T>),
		/// A proxy has set their preferences.
		ProxyPrefsSet(T::AccountId, ProxyPrefs),
	}

	// Errors inform users that something went wrong.
	#[pallet::error]
	pub enum Error<T> {
		/// a stash account has already been bonded with a controller account
		AlreadyBonded,
		/// a controller has already been paired with a stash account
		AlreadyPaired,
		/// the bond amount is below the minimum required amount
		InsufficientBond,
		/// the maximum amount of allowed proxies has been reached
		TooManyProxies,
		/// the account is not the controller for the stash account
		NotController,
		NotStash,
		NotValidator,
		NoMoreChunks,
		NoUnlockChunk,
		BadState,
		ElectionError,
		NoSuchProxy,
	}

	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		pub initial_proxies:
			Vec<(T::AccountId, T::AccountId, BalanceOf<T>, ProxyStatus)>,
		pub min_proxy_bond: BalanceOf<T>,
		pub max_proxy_count: Option<u32>,
		pub stake_redistribution_interval: u32,
		pub election_interval: u32,
		// pub history_depth: u32,
	}

	#[cfg(feature = "std")]
	impl<T: Config> Default for GenesisConfig<T> {
		fn default() -> Self {
			GenesisConfig { 
				initial_proxies: Default::default(),
				min_proxy_bond: Default::default(),
				max_proxy_count: None,
				stake_redistribution_interval: 10,
				election_interval: 50,
				// history_depth: 4u32,
			}
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
		fn build(&self) {
			Pallet::<T>::initialize_proxies(&self.initial_proxies);
			// HistoryDepth::<T>::put(self.history_depth);
			MinProxyBond::<T>::put(self.min_proxy_bond);
			if let Some(x) = self.max_proxy_count {
				MaxProxyCount::<T>::put(x);
			}
			StakeRestributionInterval::<T>::put(self.stake_redistribution_interval);
			ElectionInterval::<T>::put(self.election_interval);
		}
	}

	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
		fn offchain_worker(block_number: T::BlockNumber) {
			// if I move this into an on-chain context, then we can remove the dependency on IPFS...
			if block_number % <StakeRestributionInterval::<T>>::get().into() == 0u32.into() {
				Self::run_offchain_stake_redistribution();
			}

			if block_number % <ElectionInterval::<T>>::get().into() == 0u32.into() {
				Self::lock_winners();
			}
		}
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {

		/// Take the origin account as a stash and lock up `value` of its balance. `controller` will
		/// be the account that controls it.
		///
		/// `value` must be more than the `minimum_balance` specified by `T::Currency`.
		///
		/// The dispatch origin for this call must be _Signed_ by the stash account.
		///
		/// Emits `Bonded`.
		/// # <weight>
		/// - Independent of the arguments. Moderate complexity.
		/// - O(1).
		/// - Three extra DB entries.
		///
		/// NOTE: Two of the storage writes (`Self::bonded`, `Self::payee`) are _never_ cleaned
		/// unless the `origin` falls below _existential deposit_ and gets removed as dust.
		/// ------------------
		/// # </weight>
		#[pallet::weight(100)]
		pub fn bond(
			origin: OriginFor<T>,
			controller: <T::Lookup as StaticLookup>::Source,
			#[pallet::compact] value: BalanceOf<T>,
		) -> DispatchResult {
			let stash = ensure_signed(origin)?;

			if <Bonded<T>>::contains_key(&stash) {
				return Err(Error::<T>::AlreadyBonded.into());
			}

			let controller = T::Lookup::lookup(controller)?;

			// ensure that the proxy controller is a validator
			if !<pallet_authorities::Pallet<T>>::validators().contains(&controller) {
				return Err(Error::<T>::NotValidator.into());
			}

			if <Ledger<T>>::contains_key(&controller) {
				return Err(Error::<T>::AlreadyPaired.into())
			}

			// Reject a bond which is considered to be _dust_.
			if value < <T as pallet::Config>::Currency::minimum_balance() {
				return Err(Error::<T>::InsufficientBond.into())
			}

			frame_system::Pallet::<T>::inc_consumers(&stash).map_err(|_| Error::<T>::BadState)?;

			// You're auto-bonded forever, here. We might improve this by only bonding when
			// you actually validate/nominate and remove once you unbond __everything__.
			<Bonded<T>>::insert(&stash, &controller);
			// <Payee<T>>::insert(&stash, payee);

			let current_era = T::EraProvider::get_current_era();
			// let history_depth = Self::history_depth();
			// let last_reward_era = current_era.saturating_sub(history_depth);

			let stash_balance = <T as pallet::Config>::Currency::free_balance(&stash);
			let value = value.min(stash_balance);
			Self::deposit_event(Event::<T>::Bonded(stash.clone(), value));
			let item = StakingLedger {
				stash,
				total: value,
				active: value,
				unlocking: Default::default(),
				// claimed_rewards: (last_reward_era..current_era).collect(),
			};
			Self::update_ledger(&controller, &item);

			Ok(())
		}

		#[pallet::weight(100)]
		pub fn bond_extra(
			origin: OriginFor<T>,
			#[pallet::compact] max_additional: BalanceOf<T>,
		) -> DispatchResult {
			let stash = ensure_signed(origin)?;

			let controller = Self::bonded(&stash).ok_or(Error::<T>::NotStash)?;
			let mut ledger = Self::ledger(&controller).ok_or(Error::<T>::NotController)?;

			let stash_balance = <T as pallet::Config>::Currency::free_balance(&stash);
			if let Some(extra) = stash_balance.checked_sub(&ledger.total) {
				let extra = extra.min(max_additional);
				ledger.total += extra;
				ledger.active += extra;
				// Last check: the new active amount of ledger must be more than ED.
				ensure!(
					ledger.active >= <T as pallet::Config>::Currency::minimum_balance(),
					Error::<T>::InsufficientBond
				);

				// NOTE: ledger must be updated prior to calling `Self::weight_of`.
				Self::update_ledger(&controller, &ledger);
				// update this staker in the sorted list, if they exist in it.
				// if T::VoterList::contains(&stash) {
				// 	let _ =
				// 		T::VoterList::on_update(&stash, Self::weight_of(&ledger.stash)).defensive();
				// 	debug_assert_eq!(T::VoterList::sanity_check(), Ok(()));
				// }

				Self::deposit_event(Event::<T>::Bonded(stash, extra));
			}
			Ok(())
		}

		#[pallet::weight(100)]
		pub fn unbond(
			origin: OriginFor<T>,
			#[pallet::compact] value: BalanceOf<T>,
		) -> DispatchResult {
			let controller = ensure_signed(origin)?;
			let mut ledger = Self::ledger(&controller).ok_or(Error::<T>::NotController)?;
			ensure!(
				ledger.unlocking.len() < MaxUnlockingChunks::get() as usize,
				Error::<T>::NoMoreChunks,
			);

			let mut value = value.min(ledger.active);

			if !value.is_zero() {
				ledger.active -= value;

				// Avoid there being a dust balance left in the staking system.
				if ledger.active < <T as pallet::Config>::Currency::minimum_balance() {
					value += ledger.active;
					ledger.active = Zero::zero();
				}

				let min_active_bond = MinProxyBond::<T>::get();
				// let min_active_bond = if Nominators::<T>::contains_key(&ledger.stash) {
				// 	MinNominatorBond::<T>::get()
				// } else if Validators::<T>::contains_key(&ledger.stash) {
				// 	MinValidatorBond::<T>::get()
				// } else {
				// 	Zero::zero()
				// };

				// Make sure that the user maintains enough active bond for their role.
				// If a user runs into this error, they should chill first.
				ensure!(ledger.active >= min_active_bond, Error::<T>::InsufficientBond);

				// Note: in case there is no current era it is fine to bond one era more.
				let era = T::EraProvider::get_current_era().unwrap_or(0) + T::BondingDuration::get();
				// let era = Self::current_era().unwrap_or(0) + T::BondingDuration::get();
				if let Some(mut chunk) =
					ledger.unlocking.last_mut().filter(|chunk| chunk.era == era)
				{
					// To keep the chunk count down, we only keep one chunk per era. Since
					// `unlocking` is a FiFo queue, if a chunk exists for `era` we know that it will
					// be the last one.
					chunk.value = chunk.value.defensive_saturating_add(value)
				} else {
					ledger
						.unlocking
						.try_push(UnlockChunk { value, era })
						.map_err(|_| Error::<T>::NoMoreChunks)?;
				};
				// NOTE: ledger must be updated prior to calling `Self::weight_of`.
				Self::update_ledger(&controller, &ledger);

				// // update this staker in the sorted list, if they exist in it.
				// if T::VoterList::contains(&ledger.stash) {
				// 	let _ = T::VoterList::on_update(&ledger.stash, Self::weight_of(&ledger.stash))
				// 		.defensive();
				// }

				Self::deposit_event(Event::<T>::Unbonded(ledger.stash, value));
			}
			Ok(())
		}

		/// Declare your intention to proxy requests and assign preferences
		/// 
		/// * prefs: The proxy preferences to delcare
		/// 
		#[pallet::weight(100)]
		pub fn declare_proxy(
			origin: OriginFor<T>,
			prefs: ProxyPrefs,
		) -> DispatchResult {
			let controller = ensure_signed(origin)?;
			let ledger = Self::ledger(&controller).ok_or(Error::<T>::NotController)?;

			ensure!(ledger.active >= MinProxyBond::<T>::get(), Error::<T>::InsufficientBond);
			let stash = &ledger.stash;
			// ensure their commission is correct.
			// ensure!(prefs.commission >= MinCommission::<T>::get(), Error::<T>::CommissionTooLow);
			// Only check limits if they are not already a validator.
			if !Proxies::<T>::contains_key(stash) {
				// If this error is reached, we need to adjust the `MinValidatorBond` and start
				// calling `chill_other`. Until then, we explicitly block new validators to protect
				// the runtime.
				if let Some(max_proxies) = MaxProxyCount::<T>::get() {
					ensure!(
						Proxies::<T>::count() < max_proxies,
						Error::<T>::TooManyProxies
					);
				}
			}

			// Self::do_remove_nominator(stash);
			Self::do_add_proxy(stash, prefs.clone());
			Self::deposit_event(Event::<T>::ProxyPrefsSet(ledger.stash, prefs));

			Ok(())
		}

		#[pallet::weight(100)]
		pub fn submit_election_results(
			origin: OriginFor<T>,
			results: BTreeMap<IngestionCommand<T::AccountId, T::Balance>, Vec<T::AccountId>>,
		) ->DispatchResult {
			Ok(())
		}

		#[pallet::weight(100)]
		pub fn redistribute_stake(
			origin: OriginFor<T>,
			distribution: BTreeMap<IngestionCommand<T::AccountId, T::Balance>, u128>
		) -> DispatchResult {
			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	///
	/// Initialize proxies on gensis
	/// 
	/// * initial_proxies: A vector of proxies to initalize, containing:
	/// 					(controller, slash, balance, status)
	/// 
	fn initialize_proxies(
		initial_proxies: &Vec<(T::AccountId, T::AccountId, BalanceOf<T>, ProxyStatus)>
	) {
		for &(ref stash, ref controller, balance, ref status) in initial_proxies {
			crate::log!(
				trace,
				"inserting genesis proxy: {:?} => {:?} => {:?}",
				stash,
				balance,
				status
			);
			assert!(
				<T as pallet::Config>::Currency::free_balance(stash) >= balance,
				"Stash does not have enough balance to bond."
			);
			frame_support::assert_ok!(<Pallet<T>>::bond(
				T::Origin::from(Some(stash.clone()).into()),
				T::Lookup::unlookup(controller.clone()),
				balance,
			));
			frame_support::assert_ok!(match status {
				ProxyStatus::Proxy => <Pallet<T>>::declare_proxy(
					T::Origin::from(Some(controller.clone()).into()),
					Default::default(),
				),
				_ => Ok(()),
			});
		}
	}

	/// Add a proxy to the proxies list, along with given preferences
	/// 
	/// * who: The proxy node address to insert
	/// * prefs: The ProxyPrefs to insert
	/// 
	fn do_add_proxy(who: &T::AccountId, prefs: ProxyPrefs) {
		// mark all new proxy nodes as requiring configuration
		ProxyConfigStatus::<T>::insert(who, ProxyConfigState::Unconfigured);
		Proxies::<T>::insert(who, prefs.clone());
		let new_origin = system::RawOrigin::Signed(who.clone()).into();
		<pallet_ipfs::Pallet<T>>::update_node_config(new_origin, prefs.clone().storage_max_gb);
	}

	/// Update the ledger for a controller.
	///
	/// This will also update the stash lock.
	fn update_ledger(controller: &T::AccountId, ledger: &StakingLedger<T>) {
		<T as pallet::Config>::Currency::set_lock(STAKING_ID, &ledger.stash, ledger.total, WithdrawReasons::all());
		<Ledger<T>>::insert(controller, ledger);
	}

	// TODO: Get rid of this? I don't think it's needed really
	pub fn update_proxy_state(
		addr: T::AccountId,
		new_status: ProxyConfigState,
	) -> DispatchResult {
		<ProxyConfigStatus<T>>::insert(addr, new_status);
		Ok(())
	}

	
	fn lock_winners() {
		let ingestion_queue = T::QueueProvider::ingestion_queue().clone();
		// <IngestionCommand<T::AccountId, T::Balance>, Vec<T::AccountId>>
		let mut results_map = BTreeMap::new();
		for i in ingestion_queue.into_iter() {
			match <WeightedVote<T>>::get(i.clone()) {
				Some(mut votes) => {
					// sort votes by decreasing weight
					votes.sort_by(|u, v| u.weight.cmp(&v.weight));
					let max_weight = votes[0].weight;
					let votes = votes.into_iter().filter(|v| v.weight >= max_weight);
					let candidates: Vec<T::AccountId> = votes.map(|vote| vote.voter).collect();
					results_map.insert(i.clone(), candidates);
				},
				None => {
					log::info!("No votes were placed for this ingestion request.");
				},
			}
		}

		// // after collecting all votes, submit results on chain
		// let signer = Signer::<T, <T as pallet::Config>::AuthorityId>::all_accounts();
		// if !signer.can_sign() {
		// 	log::error!(
		// 		"No local accounts available. Consider adding one via `author_insertKey` RPC.",
		// 	);
		// }
		// let results = signer.send_signed_transaction(|_account| { 
		// 	Call::submit_election_results{
				// results_map,
		// 	}
		// });

		// for (_, res) in &results {
		// 	match res {
		// 		Ok(()) => log::info!("Submitted results successfully"),
		// 		Err(e) => log::error!("Failed to submit transaction: {:?}",  e),
		// 	}
		// }

	}

	fn run_offchain_stake_redistribution() -> Result<(), Error<T>> {
		let mut ingestion_queue = T::QueueProvider::ingestion_queue();
		let len = ingestion_queue.len();
		if len > 0 {
			// get ipfs id by reading from ipfs pallet
			let id_json = <pallet_ipfs::Pallet<T>>::fetch_identity_json().map_err(|_| Error::<T>::ElectionError).unwrap();
			// get pubkey
			let id = &id_json["ID"];
			let pubkey = id.clone().as_str().unwrap().as_bytes().to_vec();
			// get associated addr
			match <pallet_ipfs::Pallet<T>>::substrate_ipfs_bridge(&pubkey) {
				Some(addr) => {
					// get available storage in gb
					let real_storage_size_gb = <pallet_ipfs::Pallet<T>>::stats(&addr);
					// get active stake
					let active_stake: T::CurrencyBalance = <Ledger<T>>::get(&addr).unwrap().active;
					let active_stake_primitive: u128 = active_stake.saturated_into::<u128>();
					Self::offchain_redistribute_stake(addr.clone(), real_storage_size_gb.clone(), active_stake_primitive.clone(), ingestion_queue);
				},
				None => {
					// do nothing
				}
			}
		}
		Ok(())
	}

	/// A proxy places votes on ingestion commands
	///
	/// TODO: ALSO NEEDS TO SEND SIGNED TX TO REPORT THIS REDISTRIBUTION!!!!!
	fn offchain_redistribute_stake(
		proxy_addr: T::AccountId,
		total_available_storage_gb: u128,
		total_active_stake: u128,
		mut ingestion_queue: Vec<IngestionCommand<T::AccountId, T::Balance>>
	) {
		let max_wait_time_for_50gb: u32 = 10;
		// filter out items which are too large
		let mut filtered_queue: Vec<IngestionCommand<T::AccountId, T::Balance>> =
			ingestion_queue.into_iter()
				.filter(|i| i.estimated_size_gb < total_available_storage_gb)
				.collect();
		// sort by balance
		filtered_queue.sort_by(|a, b| a.balance.cmp(&b.balance));
		// Choose top k results s.t. max storage needed doesn't exceed total storage available
		let mut total_gb: u128 = 0u128;
		let mut candidate_commands: Vec<IngestionCommand<T::AccountId, T::Balance>> = Vec::new();
		for f in filtered_queue.into_iter() {
			let balance: T::Balance = f.balance;
			let balance_primitive = TryInto::<u128>::try_into(balance).ok().unwrap();
			total_gb = total_gb + balance_primitive;
			if total_gb < total_available_storage_gb {
				candidate_commands.push(f);
			} else {
				break
			}
		}
		let weight_per_gb = total_active_stake / total_gb;
		let mut results = BTreeMap::new();
		for c in candidate_commands.into_iter() {
			let weight: u128 = weight_per_gb * c.estimated_size_gb;
			results.insert(c.clone(), weight);
			// let mut votes = <WeightedVote<T>>::get(c).unwrap();
			// votes.push(Vote {
			// 	weight: weight,
			// 	voter: proxy_addr.clone(),
			// });
		}
		// TODO: submit signed tx
	}
}
