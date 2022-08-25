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
use frame_support::{assert_ok};
use mock::*;
use sp_core::Pair;

#[test]
fn data_spaces_creation_works() {
	// Given: I am a valid node with a positive balance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];
	let name: Vec<u8> = "test space".as_bytes().to_vec();
	let id = 1;
	let balance = 1;

	new_test_ext_funded(pairs).execute_with(|| {
		// WHEN: I invoke the create_storage_assets extrinsic
		assert_ok!(DataSpaces::create(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			name.clone(),
			id.clone(),
			balance.clone(),
		));

		// THEN: There is a new entry added to the metadata map
		let metadata_name_entry = crate::Metadata::<Test>::get(id.clone()).unwrap().name;
		assert_eq!(name, metadata_name_entry);
	});
}

#[test]
fn data_spaces_mint_works_for_valid_values() {
	// GIVEN: I am a valid Iris node with a positive valance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];
	let dataspace_name = "MySpace".as_bytes().to_vec();
	let balance = 1;
	let id = 1;
	let name: Vec<u8> = "test space".as_bytes().to_vec();

	new_test_ext_funded(pairs).execute_with(|| {
		// AND: I create an owned asset class
		assert_ok!(DataSpaces::create(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			name.clone(),
			id.clone(),
			balance.clone(),
		));
		// WHEN: I invoke the mint_tickets extrinsic
		assert_ok!(DataSpaces::mint(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			id.clone(),
			balance.clone(),
		));
		// THEN: The user is given a newly minted asset
		// let asset_details = <pallet_assets::Pallet<Test>>::Account::get(id.clone(), p.clone().public());
		// assert_eq!(1, asset_details.balance);
	});
}


/*
	INTEGRATION TESTS: should this be moved to a new file? YEAH runtime tests
*/
#[test]
fn data_spaces_can_associate_asset_id_with_data_space() {
	// GIVEN: I am  valid Iris node with a positive balance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];
	let dataspace_name = "MySpace".as_bytes().to_vec();
	let balance = 1;
	let dataspace_id = 1;
	let asset_id = 1;
	let name: Vec<u8> = "test space".as_bytes().to_vec();

	new_test_ext_funded(pairs).execute_with(|| {
		// AND: I create aa dataspace
		assert_ok!(DataSpaces::create(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			name.clone(),
			dataspace_id.clone(),
			balance.clone(),
		));
		// WHEN: I give myself access to the space
		assert_ok!(DataSpaces::mint(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			dataspace_id.clone(),
			balance.clone(),
		));
		// THEN: I can transfer my owned asset to another address
		assert_ok!(DataSpaces::bond(
			Origin::signed(p.clone().public()),
			dataspace_id.clone(),
			asset_id.clone(),
		));
	});
}
