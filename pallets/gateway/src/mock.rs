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

#![cfg(test)]

use super::*;
use crate::{self as pallet_gateway, Config};
use pallet_data_assets;
use frame_support::{
	parameter_types, 
	traits::{GenesisBuild, ConstU32},
	BasicExternalities,
};

use frame_system::EnsureRoot;
use pallet_session::*;
use sp_runtime::{
	impl_opaque_keys,
	testing::{Header, UintAuthorityId, TestXt},
	traits::{BlakeTwo256, IdentityLookup, OpaqueKeys, IdentifyAccount, 
		Verify, Extrinsic as ExtrinsicT, ConvertInto},
	KeyTypeId, RuntimeAppPublic, Perbill,
};
use sp_core::{
	crypto::key_types::DUMMY,
	sr25519::Signature,
	H256,
	Pair,
};
use core::convert::{TryInto, TryFrom};
use std::cell::RefCell;

pub type Balance = u64;

impl_opaque_keys! {
	pub struct MockSessionKeys {
		pub dummy: UintAuthorityId,
	}
}

impl From<UintAuthorityId> for MockSessionKeys {
	fn from(dummy: UintAuthorityId) -> Self {
		Self { dummy }
	}
}

pub const KEY_ID_A: KeyTypeId = KeyTypeId([4; 4]);
pub const KEY_ID_B: KeyTypeId = KeyTypeId([9; 4]);

#[derive(Debug, Clone, codec::Encode, codec::Decode, PartialEq, Eq)]
pub struct PreUpgradeMockSessionKeys {
	pub a: [u8; 32],
	pub b: [u8; 64],
}

impl OpaqueKeys for PreUpgradeMockSessionKeys {
	type KeyTypeIdProviders = ();

	fn key_ids() -> &'static [KeyTypeId] {
		&[KEY_ID_A, KEY_ID_B]
	}

	fn get_raw(&self, i: KeyTypeId) -> &[u8] {
		match i {
			i if i == KEY_ID_A => &self.a[..],
			i if i == KEY_ID_B => &self.b[..],
			_ => &[],
		}
	}
}

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

frame_support::construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: frame_system,
		Sesion: pallet_session,
		Vesting: pallet_vesting,
		Balances: pallet_balances,
		Assets: pallet_assets,
		Authorities: pallet_authorities,
		DataAssets: pallet_data_assets,
		Gateway: pallet_gateway,
	}
);

thread_local! {
	pub static NEXT_VALIDATORS: RefCell<Vec<(sp_core::sr25519::Public, UintAuthorityId)>> = RefCell::new(
		vec![(sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), UintAuthorityId(0)),
		(sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), UintAuthorityId(1)),
		(sp_core::sr25519::Pair::generate_with_phrase(Some("2")).0.public(), UintAuthorityId(2))]);
	pub static AUTHORITIES: RefCell<Vec<UintAuthorityId>> =
		RefCell::new(vec![UintAuthorityId(0), UintAuthorityId(1), UintAuthorityId(2)]);
	pub static FORCE_SESSION_END: RefCell<bool> = RefCell::new(false);
	pub static SESSION_LENGTH: RefCell<u64> = RefCell::new(2);
	pub static SESSION_CHANGED: RefCell<bool> = RefCell::new(false);
	pub static DISABLED: RefCell<bool> = RefCell::new(false);
	pub static BEFORE_SESSION_END_CALLED: RefCell<bool> = RefCell::new(false);
}

pub struct TestSessionHandler;
impl pallet_session::SessionHandler<sp_core::sr25519::Public> for TestSessionHandler {
	const KEY_TYPE_IDS: &'static [sp_runtime::KeyTypeId] = &[UintAuthorityId::ID];
	fn on_genesis_session<T: OpaqueKeys>(_validators: &[(sp_core::sr25519::Public, T)]) {}
	fn on_new_session<T: OpaqueKeys>(
		changed: bool,
		validators: &[(sp_core::sr25519::Public, T)],
		_queued_validators: &[(sp_core::sr25519::Public, T)],
	) {
		SESSION_CHANGED.with(|l| *l.borrow_mut() = changed);
		AUTHORITIES.with(|l| {
			*l.borrow_mut() = validators
				.iter()
				.map(|(_, id)| id.get::<UintAuthorityId>(DUMMY).unwrap_or_default())
				.collect()
		});
	}
	fn on_disabled(_validator_index: u32) {
		DISABLED.with(|l| *l.borrow_mut() = true)
	}
	fn on_before_session_ending() {
		BEFORE_SESSION_END_CALLED.with(|b| *b.borrow_mut() = true);
	}
}

pub struct TestShouldEndSession;
impl ShouldEndSession<u64> for TestShouldEndSession {
	fn should_end_session(now: u64) -> bool {
		let l = SESSION_LENGTH.with(|l| *l.borrow());
		now % l == 0 ||
			FORCE_SESSION_END.with(|l| {
				let r = *l.borrow();
				*l.borrow_mut() = false;
				r
			})
	}
}

parameter_types! {
	pub const MinimumPeriod: u64 = 5;
	pub const BlockHashCount: u64 = 250;
	pub BlockWeights: frame_system::limits::BlockWeights =
		frame_system::limits::BlockWeights::simple_max(1024);
}

impl frame_system::Config for Test {
	type BaseCallFilter = frame_support::traits::Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type DbWeight = ();
	type Origin = Origin;
	type Index = u64;
	type BlockNumber = u64;
	type Call = Call;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = sp_core::sr25519::Public;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type Event = Event;
	type BlockHashCount = BlockHashCount;
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<u64>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = ();
	type OnSetCode = ();
	type MaxConsumers = ConstU32<2>;
}

// SS58Prefix
parameter_types! {
	pub const ExistentialDeposit: u64 = 1;
}

impl pallet_balances::Config for Test {
	type MaxLocks = ();
	type MaxReserves = ();
	type ReserveIdentifier = [u8; 8];
	type Balance = u64;
	type DustRemoval = ();
	type Event = Event;
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type WeightInfo = ();
}

parameter_types! {
	pub const MinVestedTransfer: Balance = 1;
}

impl pallet_vesting::Config for Test {
	type Event = Event;
	type Currency = Balances;
	type BlockNumberToBalance = ConvertInto;
	type MinVestedTransfer = MinVestedTransfer;
	type WeightInfo = pallet_vesting::weights::SubstrateWeight<Test>;
	// `VestingInfo` encode length is 36bytes. 28 schedules gets encoded as 1009 bytes, which is the
	// highest number of schedules that encodes less than 2^10.
	const MAX_VESTING_SCHEDULES: u32 = 28;
}

parameter_types! {
	pub const DisabledValidatorsThreshold: Perbill = Perbill::from_percent(33);
}

impl pallet_session::Config for Test {
	type ValidatorId = <Self as frame_system::Config>::AccountId;
	type ValidatorIdOf = pallet_authorities::ValidatorOf<Self>;
	type ShouldEndSession = TestShouldEndSession;
	type NextSessionRotation = ();
	type SessionManager = Authorities;
	type SessionHandler = TestSessionHandler;
	type Keys = MockSessionKeys;
	type WeightInfo = ();
	type Event = Event;
}

// implement assets pallet for iris_assets 
parameter_types! {
	pub const AssetDeposit: u64 = 1;
	pub const AssetAccountDeposit: u64 = 1;
	pub const ApprovalDeposit: u64 = 1;
	pub const StringLimit: u32 = 50;
	pub const MetadataDepositBase: u64 = 1;
	pub const MetadataDepositPerByte: u64 = 1;
}

impl pallet_assets::Config for Test {
	type Event = Event;
	type Balance = u64;
	type AssetId = u32;
	type Currency = Balances;
	type ForceOrigin = frame_system::EnsureRoot<sp_core::sr25519::Public>;
	type AssetDeposit = AssetDeposit;
	type AssetAccountDeposit = AssetAccountDeposit;
	type MetadataDepositBase = MetadataDepositBase;
	type MetadataDepositPerByte = MetadataDepositPerByte;
	type ApprovalDeposit = ApprovalDeposit;
	type StringLimit = StringLimit;
	type Freezer = ();
	type WeightInfo = ();
	type Extra = ();
}

impl pallet_data_assets::Config for Test {
	type Call = Call;
	type Event = Event;
	type Currency = Balances;
	type AuthorityId = pallet_authorities::crypto::TestAuthId;
}

parameter_types! {
	pub const MinAuthorities: u32 = 2;
}

impl pallet_authorities::Config for Test {
	type AddRemoveOrigin = EnsureRoot<sp_core::sr25519::Public>;
	type Call = Call;
	type AuthorityId = pallet_authorities::crypto::TestAuthId;
	type Event = Event;
	type MinAuthorities = MinAuthorities;
}

parameter_types! {
	pub const BondingDuration: EraIndex = 3;
}

impl Config for Test {
	type Event = Event;
	type Call = Call;
	type Currency = Balances;
	type Balance = <Self as pallet_balances::Config>::Balance;
	type BondingDuration = BondingDuration;
	type EraProvider = Authorities;
}

type Extrinsic = TestXt<Call, ()>;
type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

impl frame_system::offchain::SigningTypes for Test {
	type Public = <Signature as Verify>::Signer;
	type Signature = Signature;
}

impl<LocalCall> frame_system::offchain::SendTransactionTypes<LocalCall> for Test
where
	Call: From<LocalCall>,
{
	type OverarchingCall = Call;
	type Extrinsic = Extrinsic;
}

impl<LocalCall> frame_system::offchain::CreateSignedTransaction<LocalCall> for Test
where
	Call: From<LocalCall>,
{
	fn create_transaction<C: frame_system::offchain::AppCrypto<Self::Public, Self::Signature>>(
		call: Call,
		_public: <Signature as Verify>::Signer,
		_account: AccountId,
		nonce: u64,
	) -> Option<(Call, <Extrinsic as ExtrinsicT>::SignaturePayload)> {
		Some((call, (nonce, ())))
	}
}

pub fn new_test_ext_default(validators: Vec<(sp_core::sr25519::Public, UintAuthorityId)>) -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();
	let keys: Vec<_> = validators.clone().iter()
		.map(|i| (i.0, i.0, i.1.clone().into())).collect();
	BasicExternalities::execute_with_storage(&mut t, || {
		for (ref k, ..) in &keys {
			frame_system::Pallet::<Test>::inc_providers(k);
		}
	});

	pallet_authorities::GenesisConfig::<Test> {
		initial_validators: keys.iter().map(|x| x.0).collect::<Vec<_>>(),
	}
	.assimilate_storage(&mut t)
	.unwrap();
	
	pallet_session::GenesisConfig::<Test> { keys: keys.clone() }
		.assimilate_storage(&mut t)
		.unwrap();

	let (pair1, _) = sp_core::sr25519::Pair::generate();
	let (pair2, _) = sp_core::sr25519::Pair::generate();
	let (pair3, _) = sp_core::sr25519::Pair::generate();

	pallet_balances::GenesisConfig::<Test> {
		balances: vec![(pair1.public(), 10), (pair2.public(), 20), (pair3.public(), 30)],
	}
	.assimilate_storage(&mut t)
	.unwrap();

	sp_io::TestExternalities::new(t)
}

// Build genesis storage according to the mock runtime.
pub fn new_test_ext_default_funded_validators(
	validators: Vec<(sp_core::sr25519::Public, UintAuthorityId)>,
) -> sp_io::TestExternalities {
	let mut t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();
	let keys: Vec<_> = validators.clone().iter()
		.map(|i| (i.0, i.0, i.1.clone().into())).collect();
	BasicExternalities::execute_with_storage(&mut t, || {
		for (ref k, ..) in &keys {
			frame_system::Pallet::<Test>::inc_providers(k);
		}
	});

	pallet_authorities::GenesisConfig::<Test> {
		initial_validators: keys.iter().map(|x| x.0).collect::<Vec<_>>(),
	}
	.assimilate_storage(&mut t)
	.unwrap();

	pallet_session::GenesisConfig::<Test> { keys: keys.clone() }
		.assimilate_storage(&mut t)
		.unwrap();

	let (pair2, _) = sp_core::sr25519::Pair::generate();
	let (pair3, _) = sp_core::sr25519::Pair::generate();

	pallet_balances::GenesisConfig::<Test> {
		balances: vec![
			(validators[0].0, 10), 
			(pair2.public(), 20), 
			(pair3.public(), 30)
		],
	}
	.assimilate_storage(&mut t)
	.unwrap();

	sp_io::TestExternalities::new(t)
}
