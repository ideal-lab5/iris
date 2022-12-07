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
use frame_support::assert_ok;
use mock::*;
use sp_core::Pair;
use sp_runtime::testing::UintAuthorityId;

struct TestData {
	pub p: sp_core::sr25519::Pair,
	pub _q: sp_core::sr25519::Pair,
	pub cid_vec: Vec<u8>,
	pub multiaddr_vec: Vec<u8>,
	pub name: Vec<u8>,
	pub id: u32,
	pub balance: u64,
	pub size: u128,
}

thread_local!(static TEST_CONSTANTS: TestData = TestData {
	p: sp_core::sr25519::Pair::generate().0,
	_q: sp_core::sr25519::Pair::generate().0,
	cid_vec: "QmPZv7P8nQUSh2CpqTvUeYemFyjvMjgWEs8H1Tm8b3zAm9".as_bytes().to_vec(),
	name: "test space".as_bytes().to_vec(),
	multiaddr_vec: "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWMvyvKxYcy9mjbFbXcogFSCvENzQ62ogRxHKZaksFCkAp".as_bytes().to_vec(),
	id: 1,
	balance: 1,
	size: 1,
});

#[test]
fn data_assets_initial_state() {
	new_test_ext(validators()).execute_with(|| {
		// Given: The node is initialized at block 0 with default config
		// When: I check the initial asset id and delay storage values
		let next_asset_id = crate::NextAssetId::<Test>::get();
		let delay = crate::Delay::<Test>::get();
		// Then: They are 2 and 10, respectively
		let expected_next_asset_id = 2;
		let expected_delay = 10;
		assert_eq!(next_asset_id, expected_next_asset_id);
		assert_eq!(delay, expected_delay);
		
	});
}

#[test]
fn data_assets_can_request_ingestion() {
	// Given: I am a valid node with a positive balance
	TEST_CONSTANTS.with(|test_data| {
		let pairs = vec![(test_data.p.clone().public(), 10)];
		// let expected_ingestion_cmd = crate::IngestionCommand {
		// 	owner: test_data.p.clone().public(),
		// 	cid: test_data.cid_vec.clone(),
		// 	multiaddress: test_data.multiaddr_vec.clone(),
		// 	balance: test_data.balance.clone(),
		// };
		new_test_ext_funded(pairs, validators()).execute_with(|| {
			// When: I call to create a new ingestion request
			assert_ok!(DataAssets::create_request(
				Origin::signed(test_data.p.clone().public()),
				test_data.p.clone().public(),
				test_data.balance.clone(),
				test_data.cid_vec.clone(),
				test_data.multiaddr_vec.clone(),
				test_data.balance.clone().try_into().unwrap(),
			));
			
			// Then: A new entry is added to the IngestionCommands map
			let ingestion_cmds = crate::IngestionCommands::<Test>::get(test_data.p.clone().public());
			assert_eq!(ingestion_cmds.len(), 1);
			let cmd = &ingestion_cmds[0];
			assert_eq!(cmd.owner, test_data.p.clone().public());
			assert_eq!(cmd.cid, test_data.cid_vec.clone());
			assert_eq!(cmd.multiaddress, test_data.multiaddr_vec.clone());
			assert_eq!(cmd.balance, test_data.balance.clone() as u32);
		});
	})
}

#[test]
fn data_assets_can_not_create_request_if_funds_too_low() {
	// Given: I am a valid node with a zero balance
	TEST_CONSTANTS.with(|test_data| {
		let pairs = vec![(test_data.p.clone().public(), 0)];
		new_test_ext_funded(pairs, validators()).execute_with(|| {
			// When: I call to create a new ingestion request
			assert_err!(DataAssets::create_request(
				Origin::signed(test_data.p.clone().public()),
				test_data.p.clone().public(),
				test_data.balance.clone(),
				test_data.cid_vec.clone(),
				test_data.multiaddr_vec.clone(),
				test_data.balance.clone().try_into().unwrap(),
			), crate::Error::<Test>::InsufficientBalance);
		});
	})
}

// TODO: Test QueueProvider functions
// TODO: Test ResultsHandler:create_asset_class function