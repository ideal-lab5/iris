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

// tests scenarios to cover:
// 1. Encryption
// 2. Asset Id Generation
// 3. Ingestion/Verification/AssetClassCreation Request

use super::*;
use frame_support::{assert_ok, assert_err};
use mock::*;
use sp_core::Pair;

#[test]
fn data_assets_initial_state() {
	new_test_ext().execute_with(|| {
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
	let (p, _) = sp_core::sr25519::Pair::generate();
	let (g, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];
	let multiaddr_vec = "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWMvyvKxYcy9mjbFbXcogFSCvENzQ62ogRxHKZaksFCkAp".as_bytes().to_vec();
	let cid_vec = "QmPZv7P8nQUSh2CpqTvUeYemFyjvMjgWEs8H1Tm8b3zAm9".as_bytes().to_vec();
	let name: Vec<u8> = "test.txt".as_bytes().to_vec();
	let id = 1;
	let balance = 100;
	let min_asset_balance: u64 = 1;
	let size: u128 = 1;

	let expected_ingestion_cmd = crate::IngestionCommand {
		owner: p.clone().public(),
		cid: cid_vec.clone(),
		multiaddress: multiaddr_vec.clone(),
		estimated_size_gb: size.clone(),
		balance: balance.clone(),
	};

	new_test_ext_funded(pairs).execute_with(|| {
		// When: I call to create a new ingestion request
		assert_ok!(DataAssets::create_request(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			balance.clone(),
			cid_vec.clone(),
			multiaddr_vec.clone(),
			size, // needed?
			balance.clone().try_into().unwrap(),
		));
		
		// Then: A new entry is added to the IngestionCommands map
		let ingestion_cmds = crate::IngestionCommands::<Test>::get(p.clone().public());
		assert_eq!(ingestion_cmds.len(), 1);
		let cmd = &ingestion_cmds[0];
		assert_eq!(cmd.owner, p.clone().public());
		assert_eq!(cmd.cid, cid_vec.clone());
		assert_eq!(cmd.multiaddress, multiaddr_vec.clone());
		assert_eq!(cmd.balance, balance.clone() as u32);
	});
}

#[test]
fn data_assets_can_encrypt_data_and_submit_tx() {

}

#[test]
fn data_assets_can_submit_capsule_and_kfrags() {

}
