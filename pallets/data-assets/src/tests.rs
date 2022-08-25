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
	let balance = 1;
	let min_asset_balance: u64 = 1;
	let size = 10;

	new_test_ext_funded(pairs).execute_with(|| {
		// assert_ok!(Iris::request_ingestion(
		// 	Origin::signed(p.clone().public()),
		// 	g.clone().public(),
		// 	balance,
		// 	cid_vec,
		// 	multiaddr_vec,
		// 	size, 
		// 	min_asset_balance.into(),
		// ));
	});
}
