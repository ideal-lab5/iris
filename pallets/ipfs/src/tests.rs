// // This file is part of Iris.
// //
// // Copyright (C) 2022 Ideal Labs.
// //
// // This program is free software: you can redistribute it and/or modify
// // it under the terms of the GNU General Public License as published by
// // the Free Software Foundation, either version 3 of the License, or
// // (at your option) any later version.
// //
// // This program is distributed in the hope that it will be useful,
// // but WITHOUT ANY WARRANTY; without even the implied warranty of
// // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// // GNU General Public License for more details.
// //
// // You should have received a copy of the GNU General Public License
// // along with this program. If not, see <https://www.gnu.org/licenses/>.

#![cfg(test)]

use super::*;
use crate::mock::*;
use frame_support::{assert_ok, assert_err, pallet_prelude::*};
use sp_runtime::{
	traits::{Extrinsic as ExtrinsicT},
	RuntimeAppPublic,
};
use sp_core::Pair;
use sp_core::{
	offchain::{testing, OffchainWorkerExt, TransactionPoolExt, OffchainDbExt}
};
use iris_primitives::{EncryptedBox, IngestionCommand};
use sp_keystore::{testing::KeyStore, KeystoreExt, SyncCryptoStore};
use std::sync::Arc;

struct TestData {
	pub p: sp_core::sr25519::Pair,
	pub q: sp_core::sr25519::Pair,
	pub cid_vec: Vec<u8>,
	pub name: Vec<u8>,
	pub balance: u64,
	pub public_key: Vec<u8>,
}

thread_local!(static TEST_CONSTANTS: TestData = TestData {
	p: sp_core::sr25519::Pair::generate().0,
	q: sp_core::sr25519::Pair::generate().0,
	cid_vec: "QmPZv7P8nQUSh2CpqTvUeYemFyjvMjgWEs8H1Tm8b3zAm9".as_bytes().to_vec(),
	name: "test space".as_bytes().to_vec(),
	balance: 1,
	public_key: "public_key".as_bytes().to_vec(),
});

#[test]
pub fn ipfs_can_submit_ingestion_complete() { 
	// Given: I am a valid node with a positive balance
	TEST_CONSTANTS.with(|test_data| {
		let pairs = vec![(test_data.p.clone().public(), 10)];
		let encrypted_kfrag = EncryptedBox {
			nonce: test_data.name.clone(),
			ciphertext: test_data.name.clone(),
			public_key: test_data.name.clone(),
		};
	
		let cmd = IngestionCommand {
			owner: test_data.p.public().clone(),
			cid: test_data.cid_vec.clone(),
			multiaddress: test_data.name.clone(),
			balance: test_data.balance,
		};
	
		new_test_ext_funded(test_data.p.clone()).execute_with(|| {
			// And: A user has encrypted data and submitted capsule/kfrags
			let sk_box = EncryptedBox {
				nonce: vec![102, 209, 34, 179, 214, 75, 129,  24, 44, 14, 136, 104, 179, 34, 247, 161, 168, 16, 131, 113, 43, 29, 165, 49],
				ciphertext: vec![155, 157, 182, 50, 148, 238, 223, 196, 62, 153, 134, 37, 58, 199, 71, 176, 83, 180, 73, 235, 143, 230, 221, 40, 9, 182, 4, 129, 230, 192, 13, 6, 47, 52, 14, 161, 121, 219, 204, 224, 237, 21, 139, 241, 15, 168, 189, 181], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126,  183, 5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84],
			};
			let capsule = vec![2, 7, 178, 91, 140, 23, 162, 73, 101, 16, 100, 140, 126, 128, 189, 51, 190, 43, 204, 101, 196, 187, 116, 242, 164, 135, 50, 62, 121, 21, 39, 191, 68, 3, 10, 130, 168, 14, 115, 158, 226, 143, 244, 181, 223, 210, 201, 139, 29, 65, 97, 32, 168, 140, 68, 186, 173, 72, 150, 112, 244, 66, 162, 46, 142, 226, 82, 104, 238, 89, 28, 1, 76, 159, 68, 159, 87, 201, 28, 254, 143, 212, 222, 42, 254, 44, 100, 100, 157, 252, 43, 91, 34, 219, 192, 199, 123, 25];

			assert_ok!(IrisProxy::submit_encryption_artifacts(
				Origin::signed(test_data.p.clone().public()),
				test_data.p.clone().public(),
				test_data.p.clone().public(),
				capsule,
				test_data.public_key.clone(),
				sk_box.clone(),
			));
			// And: There is an ingestion request in the queue for a gateway 
			assert_ok!(DataAssets::create_request(
				Origin::signed(test_data.p.public().clone()),
				test_data.p.public().clone(),
				test_data.balance.clone(),
				test_data.cid_vec.clone(),
				test_data.name.clone(),
				test_data.balance.clone().try_into().unwrap(),
			));
			// WHEN: I invoke the create_storage_assets extrinsic
			assert_ok!(Ipfs::submit_ingestion_completed(
				Origin::signed(test_data.p.public().clone()),
				cmd,
			));
			// // Then: A new asset class is created with asset id 1
			let asset = Assets::asset(0);
			assert_ne!(asset, None);
			assert_eq!(test_data.p.public().clone(), asset.unwrap().owner);
	
			let next_asset_id = DataAssets::next_asset_id();
			assert_eq!(1, next_asset_id);
		});
	});
}

#[test]
pub fn ipfs_fail_to_create_asset_class_if_no_staging_exists() {
	TEST_CONSTANTS.with(|test_data| {
		let encrypted_kfrag = EncryptedBox {
			nonce: test_data.name.clone(),
			ciphertext: test_data.name.clone(),
			public_key: test_data.name.clone(),
		};
		let kfrag_assignments = vec![(test_data.p.public().clone(), encrypted_kfrag.clone())];
		
	
		let cmd = IngestionCommand {
			owner: test_data.p.public().clone(),
			cid: test_data.cid_vec.clone(),
			multiaddress: test_data.name.clone(),
			balance: test_data.balance,
		};
		new_test_ext_funded(test_data.p.clone()).execute_with(|| {
			// And: There is an ingestion request in the queue for a gateway 
			assert_ok!(DataAssets::create_request(
				Origin::signed(test_data.p.public().clone()),
				test_data.p.public().clone(),
				test_data.balance.clone(),
				test_data.cid_vec.clone(),
				test_data.name.clone(),
				test_data.balance.clone().try_into().unwrap(),
			));
			// WHEN: I invoke the create_storage_assets extrinsic
			assert_ok!(Ipfs::submit_ingestion_completed(
				Origin::signed(test_data.p.public().clone()),
				cmd,
			));
	
			// Then: A new asset class is NOT created
			let asset = Assets::asset(0);
			assert_eq!(asset, None);
			// And: The next asset id is not incremented
			let next_asset_id = DataAssets::next_asset_id();
			assert_eq!(0, next_asset_id);
		});
	});
	
}

#[test]
pub fn ipfs_fail_submit_ingestion_complete_if_ingestion_cmd_not_assigned_to_you() {	
	TEST_CONSTANTS.with(|test_data| {
		// Given: I am a valid node with a positive balance
		let encrypted_kfrag = EncryptedBox {
			nonce: test_data.name.clone(),
			ciphertext: test_data.name.clone(),
			public_key: test_data.name.clone(),
		};
		let kfrag_assignments = vec![(test_data.p.public().clone(), encrypted_kfrag.clone())];
		

		let cmd = IngestionCommand {
			owner: test_data.p.public().clone(),
			cid: test_data.cid_vec.clone(),
			multiaddress: test_data.name.clone(),
			balance: test_data.balance,
		};
		new_test_ext_funded(test_data.p.clone()).execute_with(|| {
			// And: There is an ingestion request in the queue for a gateway 
			assert_ok!(DataAssets::create_request(
				Origin::signed(test_data.p.public().clone()),
				test_data.q.public().clone(),
				test_data.balance.clone(),
				test_data.cid_vec.clone(),
				test_data.name.clone(),
				test_data.balance.clone().try_into().unwrap(),
			));
			// WHEN: I invoke the create_storage_assets extrinsic
			assert_err!(Ipfs::submit_ingestion_completed(
				Origin::signed(test_data.p.public().clone()),
				cmd,
			), crate::Error::<Test>::NotAuthorized);
		});
	});
	
}

#[test]
pub fn ipfs_can_submit_ipfs_identity() {
	// Given: I am an authorized node with a positive balance
	TEST_CONSTANTS.with(|test_data| {
		let mut maddrs: Vec<OpaqueMultiaddr> = Vec::new();
		maddrs.push(OpaqueMultiaddr(test_data.public_key.clone()));

		new_test_ext_funded(test_data.p.clone()).execute_with(|| {
			// When: I call to submit my ipfs identity for the first time
			assert_ok!(Ipfs::submit_ipfs_identity(
				Origin::signed(test_data.p.clone().public()),
				test_data.public_key.clone(),
				maddrs.clone(),
			));
			// Then: my multiaddresses and pk are added as bootstrap nodes
			let bootstrap_nodes_entry = crate::BootstrapNodes::<Test>::get(test_data.public_key.clone());
			assert_eq!(maddrs.clone(), bootstrap_nodes_entry);
			// And: my node account id is associated with the ipfs pk
			let mapped_acct = crate::SubstrateIpfsBridge::<Test>::get(test_data.public_key.clone()).unwrap();
			assert_eq!(test_data.p.public().clone(), mapped_acct);
		});
	});
}

#[test]
pub fn ipfs_cannot_submit_ipfs_identity_with_another_nodes_public_key() {
	// Given: I am an authorized node with a positive balance
	TEST_CONSTANTS.with(|test_data| {
		let mut maddrs: Vec<OpaqueMultiaddr> = Vec::new();
		maddrs.push(OpaqueMultiaddr(test_data.public_key.clone()));

		new_test_ext_funded(test_data.p.clone()).execute_with(|| {
			// When: I call to submit my ipfs identity for the first time
			assert_ok!(Ipfs::submit_ipfs_identity(
				Origin::signed(test_data.p.clone().public()),
				test_data.public_key.clone(),
				maddrs.clone(),
			));
			// Then: I receive an error if I call again with the same pk but a different origin
			assert_err!(Ipfs::submit_ipfs_identity(
				Origin::signed(test_data.q.clone().public()),
				test_data.public_key.clone(),
				maddrs.clone(),
			), crate::Error::<Test>::InvalidPublicKey);
		});
	});
}

#[test]
pub fn ipfs_can_submit_config_complete() {
	// Given I am an authorized node with a positive balance
	TEST_CONSTANTS.with(|test_data| {
		let reported_storage_cap = 100u128;
		new_test_ext_funded(test_data.p.clone()).execute_with(|| {
			// When: I submit config complete
			assert_ok!(Ipfs::submit_config_complete(
				Origin::signed(test_data.p.clone().public()), 
				reported_storage_cap.clone(),
			));
			// Then: my reported storage capacity is added on chain
			let reported_stats = crate::Stats::<Test>::get(test_data.p.clone().public());
			assert_eq!(reported_storage_cap, reported_stats);
		});
	});
}

/*
	OFFCHAIN FUNCTIONALITY TESTS
*/

#[test]
pub fn ipfs_offchain_can_fetch_identity_json() {
	TEST_CONSTANTS.with(|test_data| {
		let mut t = new_test_ext_funded(test_data.p.clone());
		let (offchain, state) = testing::TestOffchainExt::new();
		t.register_extension(OffchainWorkerExt::new(offchain.clone()));	
		t.register_extension(OffchainDbExt::new(offchain.clone()));	
		{
			let mut state = state.write();
			state.expect_request(testing::PendingRequest {
				method: "POST".into(),
				uri: "http://host.docker.internal:5001/api/v0/id".into(),
				response: Some(ipfs_id_response_body()),
				sent: true,
				..Default::default()
			});
		}
		t.execute_with(|| {
			let actual_identity_result = Ipfs::fetch_identity_json().unwrap();
			let actual_id = &actual_identity_result["ID"];
			assert_eq!("123456789abcdefgt", actual_id);
		});
	});
}

#[test]
pub fn ipfs_offchain_fetch_identity_with_invalid_json() {
	TEST_CONSTANTS.with(|test_data| {
		let mut t = new_test_ext_funded(test_data.p.clone());
		let (offchain, state) = testing::TestOffchainExt::new();
		t.register_extension(OffchainWorkerExt::new(offchain.clone()));
		t.register_extension(OffchainDbExt::new(offchain.clone()));
		{
			let mut state = state.write();
			state.expect_request(testing::PendingRequest {
				method: "POST".into(),
				uri: "http://host.docker.internal:5001/api/v0/id".into(),
				response: Some(br#"{:}
				"#.to_vec()),
				sent: true,
				..Default::default()
			});
		}
		t.execute_with(|| {
			match Ipfs::fetch_identity_json() {
				Ok(json) => panic!("json should be unparseable"),
				Err(e) => {
					// as expected
					// assert_eq!(e.kind(), crate::Error::<Test>::ResponseParsingFailure);
				},
			}
		});
	});
}

#[test]
pub fn ipfs_offchain_can_verify_identity_and_submit_tx() {
	TEST_CONSTANTS.with(|test_data| {
		let mut t = new_test_ext_funded(test_data.p.clone());
		let (offchain, state) = testing::TestOffchainExt::new();
		let (pool, pool_state) = testing::TestTransactionPoolExt::new();
		let keystore = KeyStore::new();
		const PHRASE: &str =
			"news slush supreme milk chapter athlete soap sausage put clutch what kitten";
		SyncCryptoStore::sr25519_generate_new(
			&keystore,
			crate::crypto::Public::ID,
			Some(&format!("{}/hunter1", PHRASE)),
		)
		.unwrap();

		t.register_extension(OffchainWorkerExt::new(offchain.clone()));
		t.register_extension(OffchainDbExt::new(offchain.clone()));
		t.register_extension(TransactionPoolExt::new(pool));
		t.register_extension(KeystoreExt(Arc::new(keystore)));

		{
			let mut state = state.write();
			state.expect_request(testing::PendingRequest {
				method: "POST".into(),
				uri: "http://host.docker.internal:5001/api/v0/id".into(),
				response: Some(ipfs_id_response_body()),
				sent: true,
				..Default::default()
			});
		}

		let mut expected_maddrs: Vec<OpaqueMultiaddr> = Vec::new();
		expected_maddrs.push(OpaqueMultiaddr(
			"/ip4/127.0.0.1/tcp/4001/p2p/123456789abcdefgt".as_bytes().to_vec()
		));
		expected_maddrs.push(OpaqueMultiaddr(
			"/ip4/127.0.0.1/udp/4001/quic/p2p/123456789abcdefgt".as_bytes().to_vec()
		));
		expected_maddrs.push(OpaqueMultiaddr(
			"/ip4/192.168.101.47/tcp/4001/p2p/123456789abcdefgt".as_bytes().to_vec()
		));
		expected_maddrs.push(OpaqueMultiaddr(
			"/ip4/192.168.101.47/udp/4001/quic/p2p/123456789abcdefgt".as_bytes().to_vec()
		));
		expected_maddrs.push(OpaqueMultiaddr(
			"/ip4/206.176.195.179/udp/4001/quic/p2p/123456789abcdefgt".as_bytes().to_vec()
		));
		expected_maddrs.push(OpaqueMultiaddr(
			"/ip6/::1/tcp/4001/p2p/123456789abcdefgt".as_bytes().to_vec()
		));
		expected_maddrs.push(OpaqueMultiaddr(
			"/ip6/::1/udp/4001/quic/p2p/123456789abcdefgt".as_bytes().to_vec()
		));

		t.execute_with(|| {
			Ipfs::ipfs_verify_identity().unwrap();
			// And: a signed tx is added on chain
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature.unwrap().0, 0);
			assert_eq!(tx.call, mock::Call::Ipfs(crate::Call::submit_ipfs_identity { 
				public_key: "123456789abcdefgt".as_bytes().to_vec(),
				multiaddresses: expected_maddrs,
			}));
		});
	});
}

#[test]
pub fn ipfs_offchain_can_update_config() {
	TEST_CONSTANTS.with(|test_data| {
		let mut t = new_test_ext_funded(test_data.p.clone());
		let (offchain, state) = testing::TestOffchainExt::new();
		let (pool, pool_state) = testing::TestTransactionPoolExt::new();
		let keystore = KeyStore::new();
		const PHRASE: &str =
			"news slush supreme milk chapter athlete soap sausage put clutch what kitten";
		SyncCryptoStore::sr25519_generate_new(
			&keystore,
			crate::crypto::Public::ID,
			Some(&format!("{}/hunter1", PHRASE)),
		)
		.unwrap();

		t.register_extension(OffchainWorkerExt::new(offchain));
		t.register_extension(TransactionPoolExt::new(pool));
		t.register_extension(KeystoreExt(Arc::new(keystore)));

		{
			let mut state = state.write();
			state.expect_request(testing::PendingRequest {
				method: "POST".into(),
				uri: "http://host.docker.internal:5001/api/v0/config?arg=Datastore.StorageMax&arg=50GB".into(),
				response: Some(ipfs_config_update_body()),
				sent: true,
				..Default::default()
			});

			state.expect_request(testing::PendingRequest {
				method: "POST".into(),
				uri: "http://host.docker.internal:5001/api/v0/repo/stat".into(),
				response: Some(ipfs_config_show_body()),
				sent: true,
				..Default::default()
			});
		}

		t.execute_with(|| {
			// setup proxy prefs
			assert_ok!(Gateway::declare_gateway(
				Origin::signed(test_data.p.public().clone()),
				pallet_gateway::GatewayPrefs {
					max_mbps: 100,
					storage_max_gb: 100,
				}
			));
			Ipfs::ipfs_update_configs(test_data.p.clone().public()).unwrap();
			// And: a signed tx is added on chain
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature.unwrap().0, 0);
			assert_eq!(tx.call, mock::Call::Ipfs(crate::Call::submit_config_complete { 
				reported_storage_size: 100,
			}));
		});
	});
}

#[test]
pub fn ipfs_offchain_can_handle_ingestion_commands() {
	TEST_CONSTANTS.with(|test_data| {
		
		let multiaddr_vec = "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWMvyvKxYcy9mjbFbXcogFSCvENzQ62ogRxHKZaksFCkAp".as_bytes().to_vec();

		let mut t = new_test_ext_funded(test_data.p.clone());
		let (offchain, state) = testing::TestOffchainExt::new();
		let (pool, pool_state) = testing::TestTransactionPoolExt::new();


		let keystore = KeyStore::new();
		const PHRASE: &str =
			"news slush supreme milk chapter athlete soap sausage put clutch what kitten";
		SyncCryptoStore::sr25519_generate_new(
			&keystore,
			crate::crypto::Public::ID,
			Some(&format!("{}/hunter1", PHRASE)),
		)
		.unwrap();

		t.register_extension(OffchainWorkerExt::new(offchain));
		t.register_extension(TransactionPoolExt::new(pool));
		t.register_extension(KeystoreExt(Arc::new(keystore)));

		{
			let mut state = state.write();
			state.expect_request(testing::PendingRequest {
				method: "POST".into(),
				uri: "http://host.docker.internal:5001/api/v0/get?arg=QmPZv7P8nQUSh2CpqTvUeYemFyjvMjgWEs8H1Tm8b3zAm9".into(),
				response: Some(ipfs_config_show_body()),
				sent: true,
				..Default::default()
			});
		}

		let cmd = IngestionCommand {
			owner: test_data.p.public().clone(),
			cid: test_data.cid_vec.clone(),
			multiaddress: vec![47, 105, 112, 52, 47, 49, 50, 55, 46, 48, 46, 48, 46, 49, 47, 116, 99, 112, 47, 52, 48, 48, 49, 47, 112, 50, 112, 47, 49, 50, 68, 51, 75, 111, 111, 87, 77, 118, 121, 118, 75, 120, 89, 99, 121, 57, 109, 106, 98, 70, 98, 88, 99, 111, 103, 70, 83, 67, 118, 69, 78, 122, 81, 54, 50, 111, 103, 82, 120, 72, 75, 90, 97, 107, 115, 70, 67, 107, 65, 112],
			balance: test_data.balance,
		};

		t.execute_with(|| {
			// create ingestion request
			assert_ok!(DataAssets::create_request(
				Origin::signed(test_data.p.clone().public()),
				test_data.p.clone().public(),
				test_data.balance.clone(),
				test_data.cid_vec.clone(),
				multiaddr_vec.clone(),
				test_data.balance.clone().try_into().unwrap(),
			));

			Ipfs::handle_ingestion_queue(test_data.p.clone().public()).unwrap();
			// And: a signed tx is added on chain
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature.unwrap().0, 0);
			assert_eq!(tx.call, mock::Call::Ipfs(crate::Call::submit_ingestion_completed { 
				cmd: cmd,
			}));
		});
	});
}

fn ipfs_config_update_body() -> Vec<u8> {
	br#"
	{
		"Key":"Datastore.StorageMax",
		"Value":"10GB"
	}
	"#.to_vec()
}

fn ipfs_config_show_body() -> Vec<u8> {
	br#"
	{"RepoSize":27898551,"StorageMax":100,"NumObjects":172,"RepoPath":"~/ipfs","Version":"fs-repo@11"}
	"#.to_vec()
}

fn ipfs_id_response_body() -> Vec<u8> {
	br#"{
		"ID": "123456789abcdefgt",
		"PublicKey": "CAESILP+JvmogCDvobwhpD980Mpdzjhi/ykzh7ciI073Abpd",
		"Addresses": [
				"/ip4/127.0.0.1/tcp/4001/p2p/123456789abcdefgt",
				"/ip4/127.0.0.1/udp/4001/quic/p2p/123456789abcdefgt",
				"/ip4/192.168.101.47/tcp/4001/p2p/123456789abcdefgt",
				"/ip4/192.168.101.47/udp/4001/quic/p2p/123456789abcdefgt",
				"/ip4/206.176.195.179/udp/4001/quic/p2p/123456789abcdefgt",
				"/ip6/::1/tcp/4001/p2p/123456789abcdefgt",
				"/ip6/::1/udp/4001/quic/p2p/123456789abcdefgt"
		],
		"AgentVersion": "go-ipfs/0.8.0/",
		"ProtocolVersion": "ipfs/0.1.0",
		"Protocols": [
				"/ipfs/bitswap",
				"/ipfs/bitswap/1.0.0",
				"/ipfs/bitswap/1.1.0",
				"/ipfs/bitswap/1.2.0",
				"/ipfs/id/1.0.0",
				"/ipfs/id/push/1.0.0",
				"/ipfs/lan/kad/1.0.0",
				"/ipfs/ping/1.0.0",
				"/libp2p/autonat/1.0.0",
				"/libp2p/circuit/relay/0.1.0",
				"/p2p/id/delta/1.0.0",
				"/x/"
		]
	}
	"#.to_vec()
}
