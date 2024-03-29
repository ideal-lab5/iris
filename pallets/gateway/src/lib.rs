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
		Get, Currency, LockableCurrency,
		DefensiveSaturating, LockIdentifier, WithdrawReasons,
	},
	BoundedVec,
};
use scale_info::TypeInfo;
pub use pallet::*;
use sp_runtime::{
	traits::{CheckedSub, Zero},
};
use sp_std::{
	str,
	prelude::*
};
use sp_core::crypto::KeyTypeId;
use frame_system::ensure_signed;
use sp_runtime::traits::StaticLookup;
use codec::HasCompact;
use pallet_authorities::EraProvider;

pub const LOG_TARGET: &str = "runtime::proxy";
// TODO: should a new KeyTypeId be defined? e.g. b"iris"
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

const STAKING_ID: LockIdentifier = *b"staking ";

type BalanceOf<T> =
	<<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;
/// Counter for the number of eras that have passed.

pub type EraIndex = u32;
/// counter for the number of "reward" points earned by a given storage provider
pub type RewardPoint = u32;


pub type GatewayGenesisConfig<AccountId, BalanceOf> = (AccountId, AccountId, BalanceOf, ProxyStatus);

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
	/// The total amount that the node has reserved for the duration of the 
	/// election session
	#[codec(compact)]
	pub reserved: BalanceOf<T>,
	/// Any balance that is becoming free, which may eventually be transferred out of the stash
	/// (assuming it doesn't get slashed first). It is assumed that this will be treated as a first
	/// in, first out queue where the new (higher value) eras get pushed on the back.
	pub unlocking: BoundedVec<UnlockChunk<BalanceOf<T>>, MaxUnlockingChunks>,
	// / List of eras for which the stakers behind a validator have claimed rewards. Only updated
	// / for validators.
	// pub claimed_rewards: Vec<EraIndex>,
}

impl<T: Config> StakingLedger<T> {
	/// Initializes the default object using the given `validator`.
	pub fn default_from(stash: T::AccountId) -> Self {
		Self {
			stash,
			total: Zero::zero(),
			active: Zero::zero(),
			reserved: Zero::zero(),
			unlocking: Default::default(),
		}
	}


	// /// Re-bond funds that were scheduled for unlocking.
	// ///
	// /// Returns the updated ledger, and the amount actually rebonded.
	// fn rebond(mut self, value: BalanceOf<T>) -> (Self, BalanceOf<T>) {
	// 	let mut unlocking_balance = BalanceOf::<T>::zero();

	// 	while let Some(last) = self.unlocking.last_mut() {
	// 		if unlocking_balance + last.value <= value {
	// 			unlocking_balance += last.value;
	// 			self.active += last.value;
	// 			self.unlocking.pop();
	// 		} else {
	// 			let diff = value - unlocking_balance;

	// 			unlocking_balance += diff;
	// 			self.active += diff;
	// 			last.value -= diff;
	// 		}

	// 		if unlocking_balance >= value {
	// 			break
	// 		}
	// 	}

	// 	(self, unlocking_balance)
	// }
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
pub struct GatewayPrefs {
	pub max_mbps: u32,
	pub storage_max_gb: u128,
}

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	use frame_system::pallet_prelude::*;

	/// Configure the pallet by specifying the parameters and types on which it
	/// depends.
	/// TODO: probably don't need to tightly coupole the data assets pallet
	#[pallet::config]
	pub trait Config: frame_system::Config +
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
			Balance = Self::Balance,
		>;
		/// Just the `Currency::Balance` type; we have this item to allow us to constrain it to
		/// `From<u64>`.
		type Balance: sp_runtime::traits::AtLeast32BitUnsigned
			+ codec::FullCodec
			+ Copy
			+ MaybeSerializeDeserialize
			+ sp_std::fmt::Debug
			+ Default
			+ From<u64>
			+ TypeInfo
			+ MaxEncodedLen;
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
		CountedStorageMap<_, Twox64Concat, T::AccountId, GatewayPrefs>;

	/// The minimum active bond to become and maintain the role of a nominator.
	#[pallet::storage]
	pub type MinGatewayBond<T: Config> = StorageValue<_, BalanceOf<T>, ValueQuery>;

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

	/// map a gateway node to its slot
	#[pallet::storage]
	pub type Slot<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		u32,
	>;

	#[pallet::storage]
	pub type ReservedSlots<T: Config> = StorageValue<_, Vec<u32>>;

	#[pallet::storage]
	pub type CallCount<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		T::AccountId,
		u32, 
		ValueQuery
	>;

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
		GatewayPrefsSet(T::AccountId, GatewayPrefs),
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
		pub initial_proxies:Vec<GatewayGenesisConfig<T::AccountId, BalanceOf<T>>>,
		pub min_proxy_bond: BalanceOf<T>,
		pub max_proxy_count: Option<u32>,
		// pub history_depth: u32,
	}

	#[cfg(feature = "std")]
	impl<T: Config> Default for GenesisConfig<T> {
		fn default() -> Self {
			GenesisConfig { 
				initial_proxies: Default::default(),
				min_proxy_bond: Default::default(),
				max_proxy_count: None,
				// history_depth: 4u32,
			}
		}
	}

	#[pallet::genesis_build]
	impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
		fn build(&self) {
			Pallet::<T>::initialize_proxies(&self.initial_proxies);
			// HistoryDepth::<T>::put(self.history_depth);
			ReservedSlots::<T>::put(vec![2]);
			MinGatewayBond::<T>::put(self.min_proxy_bond);
			if let Some(x) = self.max_proxy_count {
				MaxProxyCount::<T>::put(x);
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

			// let current_era = T::EraProvider::get_current_era();
			// let history_depth = Self::history_depth();
			// let last_reward_era = current_era.saturating_sub(history_depth);

			let stash_balance = <T as pallet::Config>::Currency::free_balance(&stash);
			let value = value.min(stash_balance);
			Self::deposit_event(Event::<T>::Bonded(stash.clone(), value));
			let item = StakingLedger {
				stash,
				total: value,
				active: value,
				reserved: Zero::zero(),
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

				let min_active_bond = MinGatewayBond::<T>::get();
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

		/// Declare your intention to provide storage to the network
		/// 
		/// * prefs: The proxy preferences to delcare
		/// 
		#[pallet::weight(100)]
		pub fn declare_gateway(
			origin: OriginFor<T>,
			prefs: GatewayPrefs,
		) -> DispatchResult {
			let controller = ensure_signed(origin)?;
			let ledger = Self::ledger(&controller).ok_or(Error::<T>::NotController)?;

			ensure!(ledger.active >= MinGatewayBond::<T>::get(), Error::<T>::InsufficientBond);
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
			Self::deposit_event(Event::<T>::GatewayPrefsSet(ledger.stash, prefs));

			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	///
	/// Initialize proxies on gensis
	/// 
	/// * initial_proxies: A vector of proxies to initalize, containing (controller, slash, balance, status)
	/// 
	fn initialize_proxies(
		initial_proxies: &Vec<GatewayGenesisConfig<T::AccountId, BalanceOf<T>>>
	) {
		for &(ref stash, ref controller, balance, ref status) in initial_proxies {
			log::info!(
				"inserting genesis gateway: {:?} => {:?} => {:?}",
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
				ProxyStatus::Proxy => <Pallet<T>>::declare_gateway(
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
	/// * prefs: The GatewayPrefs to insert
	/// 
	fn do_add_proxy(who: &T::AccountId, prefs: GatewayPrefs) {
		Proxies::<T>::insert(who.clone(), prefs);
		let primes = vec![3, 5, 7, 9, 11, 13, 17, 19, 27, 29, 31, 37, 41, 43, 47, 51, 59, 67];
		let num_proxies = Proxies::<T>::count() as usize;
		Slot::<T>::insert(who.clone(), primes[num_proxies]);
	}

	/// Update the ledger for a controller.
	///
	/// This will also update the stash lock.
	fn update_ledger(controller: &T::AccountId, ledger: &StakingLedger<T>) {
		<T as pallet::Config>::Currency::set_lock(STAKING_ID, &ledger.stash, ledger.total, WithdrawReasons::all());
		<Ledger<T>>::insert(controller, ledger);
	}
}

/// A trait to expose information about bonded accounts and staked amounts
pub trait ProxyProvider<AccountId, Balance> {
	/// get the active balance in the staking ledger
	fn active(acct: AccountId) -> Option<Balance>;
	/// get the slash account bonded to the controller
    fn bonded(acct: AccountId) -> Option<AccountId>;
	///get the preferences specified by some stash account
	fn prefs(acct: AccountId) -> Option<GatewayPrefs>;
	/// most some active tokens to reserved
	fn reserve(acct: AccountId, balance: Balance);
	// fn unreserve(acct: AccountId, balance: Option<Balance>) -> Result<(), Error<T>>; 
	fn next_asset_id(acct: AccountId) -> u32;
}

impl<T: Config> ProxyProvider<T::AccountId, T::Balance> for Pallet<T> {

	fn active(acct: T::AccountId) -> Option<T::Balance> {
		match Ledger::<T>::get(acct) {
			Some(ledger) => {
				Some(ledger.active)
			},
			None => {
				None
			}
		}
	}

    fn bonded(acct: T::AccountId) -> Option<T::AccountId> {
        Bonded::<T>::get(acct)
    }

	fn prefs(acct: T::AccountId) -> Option<GatewayPrefs> {
		Proxies::<T>::get(acct)
	}

	fn reserve(acct: T::AccountId, balance: T::Balance) {
		if let Some(mut ledger) = <Ledger<T>>::get(acct.clone()) {
			let new_active_amount = ledger.active - balance;
			// Q: should it be >= instead?
			if new_active_amount > Zero::zero() {
				ledger.active = new_active_amount;
				ledger.reserved = balance;
				<Ledger<T>>::insert(acct, ledger);
			} else {
				// should we do anything?
			}
		}
	}
	// fn unreserve(acct: T::AccountId, balance: Option<T::Balance>) -> Result<(), Error<T>> {
	// 	Ok(())
	// }

	fn next_asset_id(acct: T::AccountId) -> u32 {
		if let Some(slot) = Slot::<T>::get(acct.clone()) {
			let index = CallCount::<T>::get(acct.clone()) + 1;
			// increment callcount
			CallCount::<T>::insert(acct, index);
			return slot * index;
		}
		0
	}
}
