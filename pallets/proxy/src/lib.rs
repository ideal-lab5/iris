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
	ensure,
	pallet_prelude::*,
	traits::{
		EstimateNextSessionRotation, Get, Currency, LockableCurrency,
		ValidatorSet, ValidatorSetWithIdentification, LockIdentifier, WithdrawReasons,
	},
};
use scale_info::TypeInfo;
pub use pallet::*;
use sp_runtime::traits::{Convert, Zero};
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
	// offchain::ipfs,
	offchain::http,
	traits::StaticLookup,
};
// use log;
use pallet_data_assets::DataCommand;

pub const LOG_TARGET: &'static str = "runtime::proxy";
// TODO: should a new KeyTypeId be defined? e.g. b"iris"
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

// pub mod crypto {
// 	// use crate::KEY_TYPE;
// 	use sp_core::crypto::KeyTypeId;
// 	use sp_core::sr25519::Signature as Sr25519Signature;
// 	use sp_runtime::app_crypto::{app_crypto, sr25519};
// 	use sp_runtime::{traits::Verify, MultiSignature, MultiSigner};
// 	use sp_std::convert::TryFrom;

// 	pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"aura");

// 	app_crypto!(sr25519, KEY_TYPE);

// 	pub struct TestAuthId;
// 	// implemented for runtime
// 	impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
// 		type RuntimeAppPublic = Public;
// 		type GenericSignature = sp_core::sr25519::Signature;
// 		type GenericPublic = sp_core::sr25519::Public;
// 	}

// 	// implemented for mock runtime in test
// 	impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
// 		for TestAuthId
// 	{
// 		type RuntimeAppPublic = Public;
// 		type GenericSignature = sp_core::sr25519::Signature;
// 		type GenericPublic = sp_core::sr25519::Public;
// 	}
// }

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

/// Reward points for storage providers of some specific assest id during an era.
#[derive(PartialEq, Encode, Decode, Default, RuntimeDebug, TypeInfo)]
pub struct EraRewardPoints<AccountId> {
	/// the total number of points
	total: RewardPoint,
	/// the reward points for individual validators, sum(i.rewardPoint in individual) = total
	individual: BTreeMap<AccountId, RewardPoint>,
}

/// Information regarding the active era (era in used in session).
#[derive(Encode, Decode, RuntimeDebug, TypeInfo)]
pub struct ActiveEraInfo {
	/// Index of era.
	pub index: EraIndex,
	/// Moment of start expressed as millisecond from `$UNIX_EPOCH`.
	///
	/// Start can be none if start hasn't been set for the era yet,
	/// Start is set on the first on_finalize of the era to guarantee usage of `Time`.
	start: Option<u64>,
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
	// / Any balance that is becoming free, which may eventually be transferred out of the stash
	// / (assuming it doesn't get slashed first). It is assumed that this will be treated as a first
	// / in, first out queue where the new (higher value) eras get pushed on the back.
	// pub unlocking: BoundedVec<UnlockChunk<BalanceOf<T>>, MaxUnlockingChunks>,
	// / List of eras for which the stakers behind a validator have claimed rewards. Only updated
	// / for validators.
	// pub claimed_rewards: Vec<EraIndex>,
}

/// Indicates the initial status of the staker.
#[derive(RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize, Clone))]
pub enum ProxyStatus {
	/// Chilling.
	Idle,
	/// Declared desire in participating as an active proxy
	Proxy,
}

/// preferences for a proxy node
#[derive(PartialEq, Eq, Clone, Encode, Decode, RuntimeDebug, TypeInfo, Default)]
pub struct ProxyPrefs {

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
		// / A stable ID for a validator.
		// type ValidatorId: Member
		// 	+ Parameter
		// 	+ MaybeSerializeDeserialize
		// 	+ MaxEncodedLen
		// 	+ TryFrom<Self::AccountId>;
		// /// A conversion from account ID to validator ID.
		// ///
		// /// Its cost must be at most one storage read.
		// type ValidatorIdOf: Convert<Self::AccountId, Option<Self::ValidatorId>>;
		// /// trait to get current session validators
		// // type ValidatorSet: ValidatorSet<Self::AccountId>;
		// /// A type for retrieving the validators supposed to be online in a session.
		// type ValidatorSet: ValidatorSetWithIdentification<Self::AccountId>;
	}

	#[pallet::type_value]
	pub(crate) fn HistoryDepthOnEmpty() -> u32 {
		84u32
	}

	#[pallet::pallet]
	#[pallet::generate_store(pub(super) trait Store)]
	#[pallet::without_storage_info]
	pub struct Pallet<T>(_);

	/// The current era index.
	///
	/// This is the latest planned era, depending on how the Session pallet queues the validator
	/// set, it might be active or not.
	#[pallet::storage]
	#[pallet::getter(fn current_era)]
	pub type CurrentEra<T> = StorageValue<
		_, EraIndex
	>;

	/// The active era information, it holds index and start.
	///
	/// The active era is the era being currently rewarded. Validator set of this era must be
	/// equal to [`SessionInterface::validators`].
	#[pallet::storage]
	#[pallet::getter(fn active_era)]
	// TODO: Do I need the ActiveEraInfo?
	pub type ActiveEra<T> = StorageValue<_, EraIndex>;
	
	// /// Rewards for the last `HISTORY_DEPTH` eras.
	// /// If reward hasn't been set or has been removed then 0 reward is returned.
	// #[pallet::storage]
	// #[pallet::getter(fn eras_reward_points)]
	// pub type ErasRewardPoints<T: Config> = StorageDoubleMap<
	// 	_, Twox64Concat, EraIndex, Twox64Concat, T::AssetId, EraRewardPoints<T::AccountId>,
	// >;

	/// The map from (wannabe) validator stash key to the preferences of that validator.
	#[pallet::storage]
	#[pallet::getter(fn proxies)]
	pub type Proxies<T: Config> =
		CountedStorageMap<_, Twox64Concat, T::AccountId, ProxyPrefs, ValueQuery>;

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
		NotValidator,
		BadState,
	}

	#[pallet::genesis_config]
	pub struct GenesisConfig<T: Config> {
		pub initial_proxies:
			Vec<(T::AccountId, T::AccountId, BalanceOf<T>, ProxyStatus)>,
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
			MinProxyBond::<T>::put(self.min_proxy_bond);
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

			let current_era = CurrentEra::<T>::get().unwrap_or(0);
			// let history_depth = Self::history_depth();
			// let last_reward_era = current_era.saturating_sub(history_depth);

			let stash_balance = <T as pallet::Config>::Currency::free_balance(&stash);
			let value = value.min(stash_balance);
			Self::deposit_event(Event::<T>::Bonded(stash.clone(), value));
			let item = StakingLedger {
				stash,
				total: value,
				active: value,
				// unlocking: Default::default(),
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
			let who = ensure_signed(origin)?;
			Ok(())
		}

		#[pallet::weight(100)]
		pub fn unbond(
			origin: OriginFor<T>,
			#[pallet::compact] max_additional: BalanceOf<T>,
		) -> DispatchResult {
			let who = ensure_signed(origin)?;
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
		// if !Validators::<T>::contains_key(who) {
		// 	// maybe update sorted list.
		// 	let _ = T::VoterList::on_insert(who.clone(), Self::weight_of(who))
		// 		.defensive_unwrap_or_default();
		// }
		Proxies::<T>::insert(who, prefs);

		// debug_assert_eq!(
		// 	Nominators::<T>::count() + Validators::<T>::count(),
		// 	T::VoterList::count()
		// );
		// debug_assert_eq!(T::VoterList::sanity_check(), Ok(()));
	}

	/// Update the ledger for a controller.
	///
	/// This will also update the stash lock.
	fn update_ledger(controller: &T::AccountId, ledger: &StakingLedger<T>) {
		<T as pallet::Config>::Currency::set_lock(STAKING_ID, &ledger.stash, ledger.total, WithdrawReasons::all());
		<Ledger<T>>::insert(controller, ledger);
	}
}

// Offence reporting and unresponsiveness management.
impl<T: Config, O: Offence<(T::AccountId, T::AccountId)>>
	ReportOffence<T::AccountId, (T::AccountId, T::AccountId), O> for Pallet<T>
{
	fn report_offence(_reporters: Vec<T::AccountId>, offence: O) -> Result<(), OffenceError> {
		let offenders = offence.offenders();

		for (v, _) in offenders.into_iter() {
			// Self::mark_for_removal(v);
		}

		Ok(())
	}

	fn is_known_offence(
		_offenders: &[(T::AccountId, T::AccountId)],
		_time_slot: &O::TimeSlot,
	) -> bool {
		false
	}
}
