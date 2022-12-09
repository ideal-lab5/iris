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

use super::*;
use frame_support::{assert_ok, assert_err};
use crate::mock::*;
use sp_core::Pair;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::SeedableRng,
};
use crypto_box::{
	SecretKey as BoxSecretKey,
};

#[test]
fn can_register_rule_executor_when_caller_is_asset_owner() {
	// Given: I am a valid node with a positive balance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let (contract_address, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];
	let id = 1;
	let balance = 1;

	new_test_ext_funded(pairs).execute_with(|| {
		// AND: I own some asset class
		assert_ok!(Assets::create(
			Origin::signed(p.clone().public()), id.clone(), p.public().clone(), balance,
		));
		// WHEN: I try to register a rule
		assert_ok!(Authorization::register_rule(
			Origin::signed(p.clone().public()),
			id.clone(),
			contract_address.public().clone(),
		));

		// THEN: There is a new entry added to the registry
		let registry = crate::Registry::<Test>::get(id.clone()).unwrap();
		assert_eq!(contract_address.public().clone(), registry);
	});
}

#[test]
fn cant_register_rules_when_not_owned() {
	// Given: I am a valid node with a positive balance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let (contract_address, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];
	let id = 1;

	new_test_ext_funded(pairs).execute_with(|| {
		// AND: I don't own the asset class
		// THEN: I receive an error when I try to register a rule
		assert_err!(Authorization::register_rule(
			Origin::signed(p.clone().public()),
			id.clone(),
			contract_address.public().clone(),
		), crate::Error::<Test>::NoSuchOwnedAssetClass);
	});
}

#[test]
fn can_submit_execution_results() {
	// Given: I am a valid node with a positive balance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let (contract_address, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];
	let id: u32 = 1;
	let balance = 1;
	let mut rng = ChaCha20Rng::seed_from_u64(31u64);
    let sk = BoxSecretKey::generate(&mut rng);

	new_test_ext_funded(pairs).execute_with(|| {
		// AND: I own some asset class
		assert_ok!(Assets::create(
			Origin::signed(p.clone().public()), 
			id.clone(), 
			p.public().clone(), 
			balance,
		));
		assert_ok!(Assets::mint(
			Origin::signed(p.clone().public()), 
			id.clone(), 
			p.public().clone(), 
			2,
		));

		// WHEN: I try to register a rule
		assert_ok!(Authorization::register_rule(
			Origin::signed(p.clone().public()),
			id.clone(),
			contract_address.public().clone(),
		));
		// AND: I submit execution results
		assert_ok!(Authorization::submit_execution_results(
			Origin::signed(contract_address.public().clone()),
			id.clone(),
			p.public().clone(),
			true,
			sk.public_key().as_bytes().to_vec(),
		));

		// THEN: A new entry is added to the lock
		let result = crate::Lock::<Test>::get(
			p.public().clone(), id.clone()
		);
		assert_eq!(true, result);
		// AND: A new capsule recovery request is created for each assigned frag holder
	});
}

#[test]
fn cant_submit_execution_results_when_contract_not_registered_for_asset() {
	// Given: I am a valid node with a positive balance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let (contract_address, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];
	let id = 1;
	let balance = 1;
	let mut rng = ChaCha20Rng::seed_from_u64(31u64);
    let sk = BoxSecretKey::generate(&mut rng);

	new_test_ext_funded(pairs).execute_with(|| {
		// AND: I own some asset class
		assert_ok!(Assets::create(
			Origin::signed(p.clone().public()), 
			id.clone(), 
			p.public().clone(), 
			balance,
		));
		assert_ok!(Assets::mint(
			Origin::signed(p.clone().public()), 
			id.clone(), 
			p.public().clone(), 
			balance,
		));
		// WHEN: I don't register a rule
		// AND: I submit execution results
		assert_ok!(Authorization::submit_execution_results(
			Origin::signed(contract_address.public().clone()),
			id.clone(),
			p.public().clone(),
			true,
			sk.public_key().as_bytes().to_vec(),
		));
		// THEN: the lock does not exist
		let result = crate::Lock::<Test>::get(
			p.public().clone(), id.clone()
		);
		assert_eq!(false, result);
	});
}
