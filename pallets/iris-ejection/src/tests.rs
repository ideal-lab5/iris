use super::*;
use frame_support::{assert_ok, assert_err};
use mock::*;
use sp_core::Pair;

#[test]
fn iris_ejection_can_register_rule_executor_when_caller_is_asset_owner() {
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
		assert_ok!(IrisEjection::register_rule(
			Origin::signed(p.clone().public()),
			id.clone(),
			contract_address.public().clone(),
		));

		// THEN: There is a new entry added to the registry
		let registry = crate::Registry::<Test>::get(id.clone());
		assert_eq!(contract_address.public().clone(), registry);
	});
}

// #[test]
// fn iris_ejection_can_unregister_rule_when_owned() {
// 	// Given: I am a valid node with a positive balance
// 	let (p, _) = sp_core::sr25519::Pair::generate();
// 	let (contract_address_1, _) = sp_core::sr25519::Pair::generate();
// 	let (contract_address_2, _) = sp_core::sr25519::Pair::generate();
// 	let pairs = vec![(p.clone().public(), 10)];
// 	let id = 1;
// 	let balance = 1;

// 	new_test_ext_funded(pairs).execute_with(|| {
// 		// AND: I own some asset class
// 		assert_ok!(Assets::create(
// 			Origin::signed(p.clone().public()), id.clone(), p.public().clone(), balance,
// 		));
// 		// WHEN: I try to register a rule
// 		assert_ok!(IrisEjection::register_rule(
// 			Origin::signed(p.clone().public()),
// 			id.clone(),
// 			contract_address_1.public().clone(),
// 		));
// 		// AND: There is a new entry added to the registry
// 		let registry_1 = crate::Registry::<Test>::get(id.clone());
// 		assert_eq!(contract_address_1.public().clone(), registry_1[0]);
// 		// AND: I do it again
// 		assert_ok!(IrisEjection::register_rule(
// 			Origin::signed(p.clone().public()),
// 			id.clone(),
// 			contract_address_2.public().clone(),
// 		));
// 		// AND: There is a new entry added to the registry
// 		let registry_2 = crate::Registry::<Test>::get(id.clone());
// 		assert_eq!(contract_address_2.public().clone(), registry_2[1]);
// 		// WHEN: I attempt to remove the rule added first
// 		assert_ok!(IrisEjection::unregister_rule(
// 			Origin::signed(p.clone().public()),
// 			id.clone(),
// 			contract_address_1.public().clone(),
// 		));
// 		 	// THEN: the rule is removed
// 		let registry_3 = crate::Registry::<Test>::get(id.clone());
// 		let registry_len = registry_3.len();
// 		assert_eq!(1, registry_len);
// 		assert_eq!(contract_address_2.public().clone(), registry_3[0]);
// 	});
}

#[test]
fn iris_ejection_cant_register_rules_when_not_owned() {
	// Given: I am a valid node with a positive balance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let (contract_address, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];
	let id = 1;
	let balance = 1;

	new_test_ext_funded(pairs).execute_with(|| {
		// AND: I don't own the asset class
		// THEN: I receive an error when I try to register a rule
		assert_err!(IrisEjection::register_rule(
			Origin::signed(p.clone().public()),
			id.clone(),
			contract_address.public().clone(),
		), crate::Error::<Test>::NoSuchOwnedAssetClass);
	});
}

// #[test]
// fn iris_ejection_cant_unregister_rule_when_not_owned() {
// 	// Given: I am a valid node with a positive balance
// 	let (p, _) = sp_core::sr25519::Pair::generate();
// 	let (contract_address_1, _) = sp_core::sr25519::Pair::generate();
// 	let (contract_address_2, _) = sp_core::sr25519::Pair::generate();
// 	let pairs = vec![(p.clone().public(), 10)];
// 	let name: Vec<u8> = "test space".as_bytes().to_vec();
// 	let id = 1;
// 	let balance = 1;

// 	new_test_ext_funded(pairs).execute_with(|| {
// 		// WHEN: I don't own the asset class
// 		// THEN: I receive an error
// 		assert_err!(IrisEjection::unregister_rule(
// 			Origin::signed(p.clone().public()),
// 			id.clone(),
// 			contract_address_1.public().clone(),
// 		), crate::Error::<Test>::NoSuchOwnedAssetClass);
// 	});
// }

#[test]
fn iris_ejection_can_submit_execution_results() {
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
		assert_ok!(IrisEjection::register_rule(
			Origin::signed(p.clone().public()),
			id.clone(),
			contract_address.public().clone(),
		));
		// AND: I submit execution results
		assert_ok!(IrisEjection::submit_execution_results(
			Origin::signed(contract_address.public().clone()),
			id.clone(),
			p.public().clone(),
			true,
		));

		// THEN: A new entry is added to the lock
		let results = crate::Lock::<Test>::get(id.clone(), p.public().clone());
		let results_count = results.len();
		assert_eq!(1, results_count);
		assert_eq!(true, results);
	});
}

#[test]
fn iris_ejection_cant_submit_execution_results_when_contract_not_registered_for_asset() {
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
		// WHEN: I don't register a rule
		// AND: I submit execution results
		assert_ok!(IrisEjection::submit_execution_results(
			Origin::signed(contract_address.public().clone()),
			id.clone(),
			p.public().clone(),
			true,
		));

		// THEN: A no new entry is added to the lock
		let results = crate::Lock::<Test>::get(id.clone(), p.public().clone());
		let results_count = results.len();
		assert_eq!(0, results_count);
	});
}