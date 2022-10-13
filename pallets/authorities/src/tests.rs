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
	authorities, new_test_ext, new_test_ext_funded, 
	Origin, Session, Test, Authorities,
};
use frame_support::{assert_noop, assert_ok, pallet_prelude::*};
use sp_runtime::testing::UintAuthorityId;
use sp_core::Pair;
use sp_core::{
	offchain::{testing, OffchainWorkerExt, TransactionPoolExt, OffchainDbExt}
};
use sp_keystore::{testing::KeyStore, KeystoreExt, SyncCryptoStore};
use std::sync::Arc;

struct TestData {
	pub validators: Vec<(sp_core::sr25519::Public, UintAuthorityId)>,
}

thread_local!(static TEST_CONSTANTS: TestData = TestData {
	validators: vec![
		(
			sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
			UintAuthorityId(0)
		),
		(
			sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
			UintAuthorityId(1)
		),
		(
			sp_core::sr25519::Pair::generate_with_phrase(Some("2")).0.public(), 
			UintAuthorityId(2)
		),
		(
			sp_core::sr25519::Pair::generate_with_phrase(Some("3")).0.public(), 
			UintAuthorityId(3)
		),
	]
});

// validator tests 
#[test]
fn simple_setup_should_work() {
	TEST_CONSTANTS.with(|test_data| {
		let v = test_data.validators.clone();
		new_test_ext(vec![v[0].clone(), v[1].clone(), v[2].clone()]).execute_with(|| {
			assert_eq!(authorities(), vec![UintAuthorityId(0), UintAuthorityId(1), UintAuthorityId(2)]);
			assert_eq!(crate::Validators::<Test>::get(), vec![v[0].0, v[1].0, v[2].0]);
			assert_eq!(Session::validators(), vec![v[0].0, v[1].0, v[2].0]);
		});
	});
}

#[test]
fn add_validator_updates_validators_list() {
	TEST_CONSTANTS.with(|test_data| {
		let v = test_data.validators.clone();
		new_test_ext(vec![v[0].clone(), v[1].clone(), v[2].clone()]).execute_with(|| {
			assert_ok!(Authorities::add_validator(Origin::root(), v[3].0));
			assert_eq!(crate::Validators::<Test>::get(), vec![v[0].0, v[1].0, v[2].0, v[3].0]);
		});
	});
	
}

#[test]
fn remove_validator_updates_validators_list() {
	TEST_CONSTANTS.with(|test_data| {
		let v = test_data.validators.clone();
		new_test_ext(vec![v[0].clone(), v[1].clone(), v[2].clone()]).execute_with(|| {
			assert_ok!(Authorities::remove_validator(Origin::root(), v[1].0));
			assert_eq!(Authorities::validators(), vec![v[0].0, v[2].0]);
		});
	});
}

#[test]
fn 
add_validator_fails_with_invalid_origin() {
	TEST_CONSTANTS.with(|test_data| {
		let v = test_data.validators.clone();
		new_test_ext(vec![v[0].clone(), v[1].clone(), v[2].clone()]).execute_with(|| {
			assert_noop!(Authorities::add_validator(
				Origin::signed(v[3].0.clone()), v[3].0), DispatchError::BadOrigin);
		});
	});
	
}

#[test]
fn remove_validator_fails_with_invalid_origin() {
	TEST_CONSTANTS.with(|test_data| {
		let v = test_data.validators.clone();	
		new_test_ext(vec![v[0].clone(), v[1].clone(), v[2].clone()]).execute_with(|| {
			assert_noop!(
				Authorities::remove_validator(Origin::signed(v[3].0.clone()), v[3].0),
				DispatchError::BadOrigin
			);
		});
	});
}

#[test]
fn duplicate_check() {
	TEST_CONSTANTS.with(|test_data| {
		let v = test_data.validators.clone();	
		new_test_ext(vec![v[0].clone(), v[1].clone(), v[2].clone()]).execute_with(|| {
			assert_ok!(Authorities::add_validator(Origin::root(), v[3].0));
			assert_eq!(Authorities::validators(), vec![v[0].0, v[1].0, v[2].0, v[3].0]);
			assert_noop!(Authorities::add_validator(Origin::root(), v[3].0), Error::<Test>::Duplicate);
		});
	});
}

#[test]
fn can_create_secrets() {
	TEST_CONSTANTS.with(|test_data| {
		let v = test_data.validators.clone();
		let mut t = new_test_ext(vec![v[0].clone(), v[1].clone(), v[2].clone()]);
		let (offchain, state) = testing::TestOffchainExt::new();
		t.register_extension(OffchainDbExt::new(offchain));
		t.execute_with(|| {
			assert_ok!(Authorities::create_secrets(Origin::signed(v[3].0.clone())));
			// check that a key was created
			let key = crate::X25519PublicKeys::<Test>::get(v[3].0.clone());
			assert_eq!(key.len(), 32);
		});
	});
}