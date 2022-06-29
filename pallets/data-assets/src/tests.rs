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
use mock::*;
use sp_core::Pair;

#[test]
fn iris_assets_initial_state() {
	new_test_ext().execute_with(|| {
		// Given: The node is initialized at block 0
		// When: I query runtime storage
		let data_queue = crate::DataQueue::<Test>::get();
		let data_space_request_queue = crate::DataSpaceRequestQueue::<Test>::get();

		let dataqueue_len = data_queue.len();
		let dataspace_queue_len = data_space_request_queue.len();

		// Then: Runtime storage is empty
		assert_eq!(dataqueue_len, 0);
		assert_eq!(dataspace_queue_len, 0);
	});
}

#[test]
fn iris_assets_create_works_for_valid_value_when_authorized_for_data_space() {
	// Given: I am a valid node with a positive balance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];
	let multiaddr_vec = "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWMvyvKxYcy9mjbFbXcogFSCvENzQ62ogRxHKZaksFCkAp".as_bytes().to_vec();
	let cid_vec = "QmPZv7P8nQUSh2CpqTvUeYemFyjvMjgWEs8H1Tm8b3zAm9".as_bytes().to_vec();
	let name: Vec<u8> = "test.txt".as_bytes().to_vec();
	let id = 1;
	let dataspace_id: u32 = 2;
	let balance = 1;

	// 
	let expected_data_command = crate::DataCommand::AddBytes(
		multiaddr_vec.clone(),
		cid_vec.clone(),
		p.clone().public(),
		id.clone(),
		balance.clone(),
		dataspace_id.clone(),
	);

	new_test_ext_funded(pairs).execute_with(|| {
		// AND: The data space exists
		assert_ok!(Assets::create(
			Origin::signed(p.clone().public()),
			dataspace_id.clone(),
			p.clone().public(),
			balance,
		));
		// AND: I am authorized to add to the data space
		assert_ok!(Assets::mint(
			Origin::signed(p.clone().public()),
			dataspace_id.clone(), 
			p.clone().public(),
			balance,
		));

		// WHEN: I invoke the create_storage_assets extrinsic
		assert_ok!(Iris::create(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			multiaddr_vec.clone(),
			cid_vec.clone(),
			dataspace_id.clone(),
			id.clone(),
			balance.clone(),
		));

		// THEN: There is a single DataCommand::AddBytes in the DataQueue
		let mut data_queue = crate::DataQueue::<Test>::get();
		let len = data_queue.len();
		assert_eq!(len, 1);
		let actual_data_command = data_queue.pop();
		assert_eq!(actual_data_command, Some(expected_data_command));
	});
}

#[test]
fn iris_assets_create_fails_when_not_authorized_for_data_space() {
	// Given: I am a valid node with a positive balance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];
	let multiaddr_vec = "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWMvyvKxYcy9mjbFbXcogFSCvENzQ62ogRxHKZaksFCkAp".as_bytes().to_vec();
	let cid_vec = "QmPZv7P8nQUSh2CpqTvUeYemFyjvMjgWEs8H1Tm8b3zAm9".as_bytes().to_vec();
	let name: Vec<u8> = "test.txt".as_bytes().to_vec();
	let id = 1;
	let dataspace_id: u32 = 2;
	let balance = 1;

	new_test_ext_funded(pairs).execute_with(|| {
		// WHEN: I invoke the create_storage_assets extrinsic
		// THEN: I get a DataSpaceNotAccessible error
		assert_err!(
			Iris::create(
				Origin::signed(p.clone().public()),
				p.clone().public(),
				multiaddr_vec.clone(),
				cid_vec.clone(),
				dataspace_id.clone(),
				id.clone(),
				balance.clone(),
			), crate::Error::<Test>::DataSpaceNotAccessible,
		);
	});
}

// #[test]
// fn iris_assets_request_data_works_for_valid_values_when_asset_class_exists() {
// 	// GIVEN: I am a valid Iris node with a positive balance
// 	let (p, _) = sp_core::sr25519::Pair::generate();
// 	let pairs = vec![(p.clone().public(), 10)];
// 	let asset_id = 1;
// 	let expected_data_command = crate::DataCommand::CatBytes(
// 		p.clone().public(),
// 		p.clone().public(),
// 		asset_id.clone(),
// 	);
// 	let cid_vec = "QmPZv7P8nQUSh2CpqTvUeYemFyjvMjgWEs8H1Tm8b3zAm9".as_bytes().to_vec();
// 	let name: Vec<u8> = "test.txt".as_bytes().to_vec();
// 	let dataspace_id: u32 = 2;
// 	let balance = 1;
// 	new_test_ext_funded(pairs).execute_with(|| {
// 		// AND: The data space exists
// 		assert_ok!(Assets::create(
// 			Origin::signed(p.clone().public()),
// 			dataspace_id.clone(),
// 			p.clone().public(),
// 			balance,
// 		));
// 		// AND: I am authorized to add to the data space
// 		assert_ok!(Assets::mint(
// 			Origin::signed(p.clone().public()),
// 			dataspace_id.clone(), 
// 			p.clone().public(),
// 			balance,
//         ));

// 		// AND: The asset class exists
// 		assert_ok!(Iris::submit_ipfs_add_results(
// 			Origin::signed(p.clone().public()),
// 			p.clone().public(),
// 			cid_vec.clone(),
// 			dataspace_id.clone(),
// 			asset_id.clone(),
// 			balance.clone().try_into().unwrap(),
// 		));
// 		// AND: I have access to the data
// 		assert_ok!(Iris::mint(
// 			Origin::signed(p.clone().public()),
// 			p.clone().public(),
// 			asset_id.clone(),
// 			balance.clone(),
// 		));

// 		// WHEN: I invoke the request_data extrinsic
// 		assert_ok!(Iris::request_bytes(
// 			Origin::signed(p.clone().public()),
// 			asset_id.clone(),
// 		));

// 		// THEN: There should be a single DataCommand::CatBytes in the DataQueue
// 		let mut data_queue = crate::DataQueue::<Test>::get();
// 		let len = data_queue.len();
// 		assert_eq!(len, 1);
// 		let actual_data_command = data_queue.pop();
// 		assert_eq!(actual_data_command, Some(expected_data_command));
// 	});
// }

#[test]
fn iris_assets_submit_ipfs_add_results_works_for_valid_values() {
	// GIVEN: I am a valid Iris node with a positive valance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];

	let cid_vec = "QmPZv7P8nQUSh2CpqTvUeYemFyjvMjgWEs8H1Tm8b3zAm9".as_bytes().to_vec();
	let id = 1;
	let balance = 1;
	let dataspace_id = 2;

	let expected_dataspace_req = DataCommand::AddToDataSpace(
		id.clone(),
		dataspace_id.clone(),
	);

	new_test_ext_funded(pairs).execute_with(|| {
		// WHEN: I invoke the submit_ipfs_add_results extrinsic
		assert_ok!(Iris::submit_ipfs_add_results(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			cid_vec.clone(),
			dataspace_id.clone(),
			id.clone(),
			balance.clone().try_into().unwrap(),
		));
		// THEN: a new request is added to the dataspace request queue
		let mut dataspace_req_queue = crate::DataSpaceRequestQueue::<Test>::get();
		let dataspace_req_queue_len = dataspace_req_queue.len();
		assert_eq!(1, dataspace_req_queue_len);
		let mut actual_dataspace_req = dataspace_req_queue.pop();
		assert_eq!(Some(expected_dataspace_req), actual_dataspace_req);

		// AND: A new entry is added to the AssetClassOwnership StorageDoubleMap
		let new_asset_exists = crate::AssetClassOwnership::<Test>::get(p.public().clone()).contains(&id);
		assert_eq!(new_asset_exists, true);

		// AND: The asset ids map contains the new asset id
		let mut asset_ids = crate::AssetIds::<Test>::get();
		let asset_ids_len = asset_ids.len();
		assert_eq!(1, asset_ids_len);
		let mut asset_id = asset_ids.pop();
		assert_eq!(Some(id.clone()), asset_id);
	});
}

#[test]
fn iris_assets_mint_tickets_works_for_valid_values() {
	// GIVEN: I am a valid Iris node with a positive valance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];
	let cid_vec = "QmPZv7P8nQUSh2CpqTvUeYemFyjvMjgWEs8H1Tm8b3zAm9".as_bytes().to_vec();
	let balance = 1;
	let id = 1;
	let dataspace_id = 2;

	new_test_ext_funded(pairs).execute_with(|| {
		// AND: I create an owned asset class
		assert_ok!(Iris::submit_ipfs_add_results(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			cid_vec.clone(),
			dataspace_id.clone(),
			id.clone(),
			balance.clone(),
		));
		// WHEN: I invoke the mint_tickets extrinsic
		assert_ok!(Iris::mint(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			id.clone(),
			balance.clone(),
		));
		// THEN: new assets are created and awarded to the benficiary
		// AND: A new entry is added to the AssetAccess StorageDoubleMap
		let asset_id_is_owned = crate::AssetAccess::<Test>::get(p.clone().public()).contains(&id);
		assert_eq!(asset_id_is_owned, true);
	});
}

#[test]
fn iris_assets_can_transer_assets() {
	// GIVEN: I am  valid Iris node with a positive balance	// GIVEN: I am a valid Iris node with a positive valance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let (p2, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10), (p2.clone().public(), 10)];
	let cid_vec = "QmPZv7P8nQUSh2CpqTvUeYemFyjvMjgWEs8H1Tm8b3zAm9".as_bytes().to_vec();
	let balance = 1;
	let id = 1;
	let dataspace_id = 2;

	new_test_ext_funded(pairs).execute_with(|| {
		// AND: I create an owned asset class
		assert_ok!(Iris::submit_ipfs_add_results(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			cid_vec.clone(),
			dataspace_id.clone(),
			id.clone(),
			balance.clone(),
		));
		// WHEN: I invoke the mint_tickets extrinsic
		assert_ok!(Iris::mint(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			id.clone(),
			balance.clone(),
		));
		// THEN: I can transfer my owned asset to another address
		assert_ok!(Iris::transfer_asset(
			Origin::signed(p.clone().public()),
			p2.clone().public(),
			id.clone(),
			balance.clone(),
		));
	});
}

#[test]
fn iris_assets_can_burn_asset() {
	// Given: I am a valid node with a positive balance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];
	let cid_vec = "QmPZv7P8nQUSh2CpqTvUeYemFyjvMjgWEs8H1Tm8b3zAm9".as_bytes().to_vec();
	let id = 1;
	let balance = 2;
	let dataspace_id = 2;

	new_test_ext_funded(pairs).execute_with(|| {
		// GIVEN: I create an asset class
		assert_ok!(Iris::submit_ipfs_add_results(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			cid_vec.clone(),
			dataspace_id.clone(),
			id.clone(),
			balance.clone(),
		));
		// AND: I mint some assets
		assert_ok!(Iris::mint(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			id.clone(),
			balance.clone(),
		));
		// WHEN: I burn 1 asset
		assert_ok!(Iris::burn(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			id.clone(),
			1,
		));
	});	
}
