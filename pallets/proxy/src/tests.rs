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
use crate::mock::{
	authorities, new_test_ext_default, new_test_ext_default_funded_validators,
	Origin, Session, Test, DataAssets, Assets, Proxy,
};
use frame_support::{assert_noop, assert_ok, assert_err, pallet_prelude::*};
use sp_runtime::testing::UintAuthorityId;
use sp_core::Pair;
use sp_core::{
	offchain::{testing, OffchainWorkerExt, TransactionPoolExt, OffchainDbExt}
};
use sp_keystore::{testing::KeyStore, KeystoreExt, SyncCryptoStore};
use std::sync::Arc;

// validator tests 
#[test]
fn iris_proxy_simple_setup_should_work() {
	// GIVEN: There are two validator nodes
	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
		UintAuthorityId(0)
	);
	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
		UintAuthorityId(1)
	);
	// AND: I have properly setup the mock runtime
	new_test_ext_default(vec![v0.clone(), v1.clone()]).execute_with(|| {
		// WHEN: The runtime is initiated with default genesis values
		// THEN: The values of the proxy pallet match the default values
		assert_eq!(0, crate::Proxies::<Test>::count());
		assert_eq!(0, crate::MinProxyBond::<Test>::get());
		assert_eq!(None, crate::MaxProxyCount::<Test>::get());
	});
}

#[test]
fn proxy_bond_with_valid_values_should_work() {
	// GIVEN: There are two validator nodes
	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
		UintAuthorityId(0)
	);
	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
		UintAuthorityId(1)
	);
	// AND: I have properly setup the mock runtime
	new_test_ext_default_funded_validators(vec![v0.clone(), v1.clone()]).execute_with(|| {
		// WHEN: I have properly setup the runtime
		// AND: I attempt to bond my controller to my stash
		// AND: My controller is my stash (wlog)
		// THEN: the bonding is successful
		assert_ok!(Proxy::bond(
			Origin::signed(v0.0.clone()),
			v0.0.clone(),
			1,
		));
		// AND: The bonds are updated
		assert_eq!(Some(v0.0.clone()), crate::Bonded::<Test>::get(v0.0.clone()));
		// AND: The ledger is updated
		let expect_staking_ledger = crate::StakingLedger {
			stash: v0.0.clone(),
			total: 1,
			active: 1,
		};
		assert_eq!(Some(expect_staking_ledger), crate::Ledger::<Test>::get(v0.0.clone()));
	});
}

#[test]
fn proxy_bond_not_validator_err_when_not_validator() {
	// GIVEN: There are two validator nodes
	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
		UintAuthorityId(0)
	);
	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
		UintAuthorityId(1)
	);
	let (not_validator, _) = sp_core::sr25519::Pair::generate();
	// AND: I have properly setup the mock runtime
	new_test_ext_default_funded_validators(vec![v0.clone(), v1.clone()]).execute_with(|| {
		// WHEN: I have properly setup the runtime
		// AND: I attempt to bond my controller to my stash
		// AND: I am NOT a validator
		// THEN: The bond fails
		assert_err!(Proxy::bond(
			Origin::signed(not_validator.clone().public()),
			not_validator.clone().public(),
			1,
		), crate::Error::<Test>::NotValidator);
	});
}

#[test]
fn proxy_bond_already_bonded_err_when_bonded() {
	// GIVEN: There are two validator nodes
	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
		UintAuthorityId(0)
	);
	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
		UintAuthorityId(1)
	);
	let (not_validator, _) = sp_core::sr25519::Pair::generate();
	// AND: I have properly setup the mock runtime
	new_test_ext_default_funded_validators(vec![v0.clone(), v1.clone()]).execute_with(|| {
		// WHEN: I have properly setup the runtime
		// AND: I attempt to bond my controller to my stash
		// AND: My controller is my stash (wlog)
		// THEN: the bonding is successful
		assert_ok!(Proxy::bond(
			Origin::signed(v0.0.clone()),
			v0.0.clone(),
			1,
		));
		// AND: If I try to bond again
		// THEN: The bond fails
		assert_err!(Proxy::bond(
			Origin::signed(v0.0.clone()), 
			v0.0.clone(),
			1,
		), crate::Error::<Test>::AlreadyBonded);
	});
}

#[test]
fn proxy_bond_already_paired_when_controller_in_ledger() {
	// GIVEN: There are two validator nodes
	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
		UintAuthorityId(0)
	);
	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
		UintAuthorityId(1)
	);
	let (not_validator, _) = sp_core::sr25519::Pair::generate();
	// AND: I have properly setup the mock runtime
	new_test_ext_default_funded_validators(vec![v0.clone(), v1.clone()]).execute_with(|| {
		// WHEN: I have properly setup the runtime
		// AND: I attempt to bond my controller to my stash
		// AND: My controller is my stash (wlog)
		// THEN: the bonding is successful
		assert_ok!(Proxy::bond(
			Origin::signed(v0.0.clone()),
			v0.0.clone(),
			1,
		));
		// AND: If I try to bond the same controller to a different stash
		// THEN: I receive an AlreadyPaired error
		assert_err!(Proxy::bond(
			Origin::signed(v1.0.clone()), 
			v0.0.clone(),
			1,
		), crate::Error::<Test>::AlreadyPaired);
	});
}

#[test]
fn proxy_bond_insufficient_balance_err_when_value_too_low() {
	// GIVEN: There are two validator nodes
	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
		UintAuthorityId(0)
	);
	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
		UintAuthorityId(1)
	);
	let (not_validator, _) = sp_core::sr25519::Pair::generate();
	// AND: I have properly setup the mock runtime
	new_test_ext_default_funded_validators(vec![v0.clone(), v1.clone()]).execute_with(|| {
		// WHEN: I have properly setup the runtime
		// AND: I attempt to bond my controller to my stash with a low balance
		// AND: My controller is my stash (wlog)
		// THEN: the bonding fails with an InsufficientBond error
		assert_err!(Proxy::bond(
			Origin::signed(v1.0.clone()), 
			v1.0.clone(),
			0,
		), crate::Error::<Test>::InsufficientBond);
	});
}
