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
	authorities, new_test_ext_default, new_test_ext_default_funded,
	Origin, Session, Test, DataAssets, Assets, Proxy,
};
use frame_support::{assert_noop, assert_ok, pallet_prelude::*};
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
	// GIVEN: I have properly setup the mock runtime
	new_test_ext_default().execute_with(|| {
		// WHEN: The runtime is initiated with default genesis values
		// THEN: The values of the proxy pallet match the default values
		assert_eq!(0, crate::Proxies::<Test>::count());
		assert_eq!(0, crate::MinProxyBond::<Test>::get());
		assert_eq!(None, crate::MaxProxyCount::<Test>::get());
	});
}

#[test]
fn iris_proxy_bond_with_valid_values_should_work() {
	// GIVEN: I have a funded pair
	let (p, _) = sp_core::sr25519::Pair::generate();
	new_test_ext_default_funded(p.clone()).execute_with(|| {
		// WHEN: I have properly setup the runtime
		// AND: I attempt to bond my controller to my stash
		// AND: My controller is my stash (wlog)
		// THEN: the bonding is successful
		assert_ok!(Proxy::bond(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			1,
		));
	});
}

// #[test]
// fn iris_session_add_validator_updates_validators_list() {
// 	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
// 		UintAuthorityId(0)
// 	);
// 	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
// 		UintAuthorityId(1)
// 	);
// 	let v2: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("2")).0.public(), 
// 		UintAuthorityId(2)
// 	);
// 	let v3: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("3")).0.public(), 
// 		UintAuthorityId(3)
// 	);
	
// 	new_test_ext(vec![v0.clone(), v1.clone(), v2.clone()]).execute_with(|| {
// 		assert_ok!(Authorities::add_validator(Origin::root(), v3.0));
// 		assert_eq!(crate::Validators::<Test>::get(), vec![v0.0, v1.0, v2.0, v3.0]);
// 	});
// }

// #[test]
// fn iris_session_remove_validator_updates_validators_list() {
// 	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
// 		UintAuthorityId(0)
// 	);
// 	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
// 		UintAuthorityId(1)
// 	);
// 	let v2: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("2")).0.public(), 
// 		UintAuthorityId(2)
// 	);
// 	new_test_ext(vec![v0.clone(), v1.clone(), v2.clone()]).execute_with(|| {
// 		assert_ok!(Authorities::remove_validator(Origin::root(), v1.0));
// 		assert_eq!(Authorities::validators(), vec![v0.0, v2.0]);
// 	});
// }

// #[test]
// fn iris_session_add_validator_fails_with_invalid_origin() {
// 	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
// 		UintAuthorityId(0)
// 	);
// 	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
// 		UintAuthorityId(1)
// 	);
// 	let v2: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("2")).0.public(), 
// 		UintAuthorityId(2)
// 	);
// 	let v3 = sp_core::sr25519::Pair::generate_with_phrase(Some("3")).0.public();
// 	new_test_ext(vec![v0.clone(), v1.clone(), v2.clone()]).execute_with(|| {
// 		assert_noop!(Authorities::add_validator(Origin::signed(v3.clone()), v3), DispatchError::BadOrigin);
// 	});
// }

// #[test]
// fn iris_session_remove_validator_fails_with_invalid_origin() {
// 	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
// 		UintAuthorityId(0)
// 	);
// 	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
// 		UintAuthorityId(1)
// 	);
// 	let v2: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("2")).0.public(), 
// 		UintAuthorityId(2)
// 	);
// 	let v3 = sp_core::sr25519::Pair::generate_with_phrase(Some("3")).0.public();
// 	new_test_ext(vec![v0.clone(), v1.clone(), v2.clone()]).execute_with(|| {
// 		assert_noop!(
// 			Authorities::remove_validator(Origin::signed(v3.clone()), v3),
// 			DispatchError::BadOrigin
// 		);
// 	});
// }

// #[test]
// fn iris_session_duplicate_check() {
// 	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
// 		UintAuthorityId(0)
// 	);
// 	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
// 		UintAuthorityId(1)
// 	);
// 	let v2: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("2")).0.public(), 
// 		UintAuthorityId(2)
// 	);
// 	let v3: (sp_core::sr25519::Public, UintAuthorityId) = (
// 		sp_core::sr25519::Pair::generate_with_phrase(Some("3")).0.public(), 
// 		UintAuthorityId(3)
// 	);
// 	new_test_ext(vec![v0.clone(), v1.clone(), v2.clone()]).execute_with(|| {
// 		assert_ok!(Authorities::add_validator(Origin::root(), v3.0));
// 		assert_eq!(Authorities::validators(), vec![v0.0, v1.0, v2.0, v3.0]);
// 		assert_noop!(Authorities::add_validator(Origin::root(), v3.0), Error::<Test>::Duplicate);
// 	});
// }
