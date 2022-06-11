//! Tests for the Validator Set pallet.

#![cfg(test)]

use super::*;
use crate::mock::{authorities, new_test_ext, new_test_ext_funded, Origin, Session, Test, IrisSession, IrisAssets};
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
fn iris_session_simple_setup_should_work() {
	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
		UintAuthorityId(0)
	);
	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
		UintAuthorityId(1)
	);
	let v2: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("2")).0.public(), 
		UintAuthorityId(2)
	);

	new_test_ext(vec![v0.clone(), v1.clone(), v2.clone()]).execute_with(|| {
		// assert_eq!(authorities(), vec![v0.1, v1.1, v2.1]);
		assert_eq!(authorities(), vec![UintAuthorityId(0), UintAuthorityId(1), UintAuthorityId(2)]);
		assert_eq!(crate::Validators::<Test>::get(), vec![v0.0, v1.0, v2.0]);
		assert_eq!(Session::validators(), vec![v0.0, v1.0, v2.0]);
	});
}

#[test]
fn iris_session_add_validator_updates_validators_list() {
	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
		UintAuthorityId(0)
	);
	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
		UintAuthorityId(1)
	);
	let v2: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("2")).0.public(), 
		UintAuthorityId(2)
	);
	let v3: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("3")).0.public(), 
		UintAuthorityId(3)
	);
	
	new_test_ext(vec![v0.clone(), v1.clone(), v2.clone()]).execute_with(|| {
		assert_ok!(IrisSession::add_validator(Origin::root(), v3.0));
		assert_eq!(crate::Validators::<Test>::get(), vec![v0.0, v1.0, v2.0, v3.0]);
	});
}

#[test]
fn iris_session_remove_validator_updates_validators_list() {
	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
		UintAuthorityId(0)
	);
	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
		UintAuthorityId(1)
	);
	let v2: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("2")).0.public(), 
		UintAuthorityId(2)
	);
	new_test_ext(vec![v0.clone(), v1.clone(), v2.clone()]).execute_with(|| {
		assert_ok!(IrisSession::remove_validator(Origin::root(), v1.0));
		assert_eq!(IrisSession::validators(), vec![v0.0, v2.0]);
	});
}

#[test]
fn iris_session_add_validator_fails_with_invalid_origin() {
	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
		UintAuthorityId(0)
	);
	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
		UintAuthorityId(1)
	);
	let v2: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("2")).0.public(), 
		UintAuthorityId(2)
	);
	let v3 = sp_core::sr25519::Pair::generate_with_phrase(Some("3")).0.public();
	new_test_ext(vec![v0.clone(), v1.clone(), v2.clone()]).execute_with(|| {
		assert_noop!(IrisSession::add_validator(Origin::signed(v3.clone()), v3), DispatchError::BadOrigin);
	});
}

#[test]
fn iris_session_remove_validator_fails_with_invalid_origin() {
	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
		UintAuthorityId(0)
	);
	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
		UintAuthorityId(1)
	);
	let v2: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("2")).0.public(), 
		UintAuthorityId(2)
	);
	let v3 = sp_core::sr25519::Pair::generate_with_phrase(Some("3")).0.public();
	new_test_ext(vec![v0.clone(), v1.clone(), v2.clone()]).execute_with(|| {
		assert_noop!(
			IrisSession::remove_validator(Origin::signed(v3.clone()), v3),
			DispatchError::BadOrigin
		);
	});
}

#[test]
fn iris_session_duplicate_check() {
	let v0: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("0")).0.public(), 
		UintAuthorityId(0)
	);
	let v1: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("1")).0.public(), 
		UintAuthorityId(1)
	);
	let v2: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("2")).0.public(), 
		UintAuthorityId(2)
	);
	let v3: (sp_core::sr25519::Public, UintAuthorityId) = (
		sp_core::sr25519::Pair::generate_with_phrase(Some("3")).0.public(), 
		UintAuthorityId(3)
	);
	new_test_ext(vec![v0.clone(), v1.clone(), v2.clone()]).execute_with(|| {
		assert_ok!(IrisSession::add_validator(Origin::root(), v3.0));
		assert_eq!(IrisSession::validators(), vec![v0.0, v1.0, v2.0, v3.0]);
		assert_noop!(IrisSession::add_validator(Origin::root(), v3.0), Error::<Test>::Duplicate);
	});
}

// storage provider tests

#[test]
fn iris_session_join_storage_pool() {
	let (p, _) = sp_core::sr25519::Pair::generate();
	let (offchain, state) = testing::TestOffchainExt::new();
	let (pool, _) = testing::TestTransactionPoolExt::new();
	const PHRASE: &str =
		"news slush supreme milk chapter athlete soap sausage put clutch what kitten";
	let keystore = KeyStore::new();
	SyncCryptoStore::sr25519_generate_new(
		&keystore,
		crate::KEY_TYPE,
		Some(&format!("{}/geralt1", PHRASE)),
	)
	.unwrap();

	let mut t = new_test_ext_funded(p.clone());
	t.register_extension(OffchainWorkerExt::new(offchain));
	t.register_extension(TransactionPoolExt::new(pool));
	t.register_extension(KeystoreExt(Arc::new(keystore)));

	let multiaddr_vec = "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWMvyvKxYcy9mjbFbXcogFSCvENzQ62ogRxHKZaksFCkAp".as_bytes().to_vec();
	let cid_vec = "QmPZv7P8nQUSh2CpqTvUeYemFyjvMjgWEs8H1Tm8b3zAm9".as_bytes().to_vec();
	let bytes = "hello test".as_bytes().to_vec();
	let name: Vec<u8> = "test.txt".as_bytes().to_vec();
	let id = 1;
	let balance = 1;
	let dataspace_id: u32 = 2;
	// mock IPFS calls
	{	
		let mut state = state.write();
		// connect to external node
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			response: Some(IpfsResponse::Success),
			..Default::default()
		});
		// fetch data
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			id: sp_core::offchain::IpfsRequestId(0),
			response: Some(IpfsResponse::CatBytes(bytes.clone())),
			..Default::default()
		});
		// disconnect from the external node
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			response: Some(IpfsResponse::Success),
			..Default::default()
		});
		// add bytes to your local node 
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			response: Some(IpfsResponse::AddBytes(cid_vec.clone())),
			..Default::default()
		});
		// get ipfs id
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			// id: sp_core::offchain::IpfsRequestId(5),
			response: Some(IpfsResponse::Identity(Vec::new(), Vec::new())),
			..Default::default()
		});
		// insert pin
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			response: Some(IpfsResponse::Success),
			..Default::default()
		});
	}

	t.execute_with(|| {
		assert_ok!(IrisSession::add_validator(Origin::root(), p.clone().public()));
		// WHEN: I invoke the create_storage_assets extrinsic
		assert_ok!(IrisAssets::create(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			multiaddr_vec.clone(),
			cid_vec.clone(),
			name.clone(),
			dataspace_id.clone(),
			id.clone(),
			balance.clone(),
		));
		// THEN: the offchain worker adds data to IPFS
		assert_ok!(IrisSession::handle_data_requests());
		assert_ok!(IrisSession::submit_ipfs_add_results(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			cid_vec.clone(),
			id.clone(),
			balance.clone(),
			dataspace_id.clone(),
		));
		// AND: the data queue is cleared after the command is processed
		// let data_queue = IrisAssets::data_queue();
		// let len = data_queue.len();
		// assert_eq!(len, 0);
		// AND: the request is removed from the data queue
		assert_ok!(IrisSession::join_storage_pool(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			id.clone(),
		));
		// AND: I receive a reward point
		let era_reward_points = crate::ErasRewardPoints::<Test>::get(0, id.clone());
		assert_eq!(4, era_reward_points.as_ref().unwrap().total);
		assert_eq!(1u32, *era_reward_points.unwrap().individual.entry(p.clone().public()).or_default());
	});
}

// test OCW functionality
// can add bytes to network
#[test]
fn iris_session_validators_receive_reward_when_add_bytes_to_ipfs() {
	// new keypair
	let (p, _) = sp_core::sr25519::Pair::generate();
	let (offchain, state) = testing::TestOffchainExt::new();
	let (pool, _) = testing::TestTransactionPoolExt::new();
	const PHRASE: &str =
		"news slush supreme milk chapter athlete soap sausage put clutch what kitten";
	let keystore = KeyStore::new();
	SyncCryptoStore::sr25519_generate_new(
		&keystore,
		crate::KEY_TYPE,
		Some(&format!("{}/geralt1", PHRASE)),
	)
	.unwrap();

	let mut t = new_test_ext_funded(p.clone());
	t.register_extension(OffchainWorkerExt::new(offchain));
	t.register_extension(TransactionPoolExt::new(pool));
	t.register_extension(KeystoreExt(Arc::new(keystore)));

	let multiaddr_vec = "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWMvyvKxYcy9mjbFbXcogFSCvENzQ62ogRxHKZaksFCkAp".as_bytes().to_vec();
	let cid_vec = "QmPZv7P8nQUSh2CpqTvUeYemFyjvMjgWEs8H1Tm8b3zAm9".as_bytes().to_vec();
	let bytes = "hello test".as_bytes().to_vec();
	let name: Vec<u8> = "test.txt".as_bytes().to_vec();
	let id = 1;
	let balance = 1;
	let dataspace_id: u32 = 2;
	// mock IPFS calls
	{	
		let mut state = state.write();
		// connect to external node
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			response: Some(IpfsResponse::Success),
			..Default::default()
		});
		// fetch data
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			id: sp_core::offchain::IpfsRequestId(0),
			response: Some(IpfsResponse::CatBytes(bytes.clone())),
			..Default::default()
		});
		// disconnect from the external node
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			response: Some(IpfsResponse::Success),
			..Default::default()
		});
		// add bytes to your local node 
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			response: Some(IpfsResponse::AddBytes(cid_vec.clone())),
			..Default::default()
		});
	}

	t.execute_with(|| {
		assert_ok!(IrisSession::add_validator(Origin::root(), p.clone().public()));
		// WHEN: I invoke the create_storage_assets extrinsic
		assert_ok!(IrisAssets::create(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			multiaddr_vec.clone(),
			cid_vec.clone(),
			name.clone(),
			dataspace_id.clone(),
			id.clone(),
			balance.clone(),
		));
		// THEN: the offchain worker adds data to IPFS
		assert_ok!(IrisSession::handle_data_requests());
		assert_ok!(IrisSession::submit_ipfs_add_results(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			cid_vec.clone(),
			id.clone(),
			balance.clone(),
			dataspace_id.clone(),
		));
		// AND: each validator is given a reward point
		let mut eras_reward_points = crate::ErasRewardPoints::<Test>::get(0, id.clone()).unwrap();
		assert_eq!(4, eras_reward_points.total);
		// TODO: should move the unwrap to it's own declaration
		for validator in crate::Validators::<Test>::get() {
			assert_eq!(1u32, *eras_reward_points.individual.entry(validator).or_default());
		}
	});
}

// can fetch bytes and add to offchain storage
#[test]
fn iris_session_can_fetch_bytes_and_add_to_offchain_storage() {
	let (p, _) = sp_core::sr25519::Pair::generate();
	let (offchain, state) = testing::TestOffchainExt::new();
	let (pool, _) = testing::TestTransactionPoolExt::new();
	const PHRASE: &str =
		"news slush supreme milk chapter athlete soap sausage put clutch what kitten";
	let keystore = KeyStore::new();
	SyncCryptoStore::sr25519_generate_new(
		&keystore,
		crate::KEY_TYPE,
		Some(&format!("{}/geralt1", PHRASE)),
	)
	.unwrap();

	let mut t = new_test_ext_funded(p.clone());
	t.register_extension(OffchainWorkerExt::new(offchain.clone()));
	t.register_extension(OffchainDbExt::new(offchain));
	t.register_extension(TransactionPoolExt::new(pool));
	t.register_extension(KeystoreExt(Arc::new(keystore)));

	let multiaddr_vec = "/ip4/127.0.0.1/tcp/4001/p2p/12D3KooWMvyvKxYcy9mjbFbXcogFSCvENzQ62ogRxHKZaksFCkAp".as_bytes().to_vec();
	let cid_vec = "QmPZv7P8nQUSh2CpqTvUeYemFyjvMjgWEs8H1Tm8b3zAm9".as_bytes().to_vec();
	let bytes = "hello test".as_bytes().to_vec();
	let name: Vec<u8> = "test.txt".as_bytes().to_vec();
	let id = 1;
	let balance = 1;
	let dataspace_id: u32 = 2;
	// mock IPFS calls
	{	
		let mut state = state.write();

		// connect to external node
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			id: sp_core::offchain::IpfsRequestId(0),
			response: Some(IpfsResponse::Success),
			..Default::default()
		});
		// fetch data
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			id: sp_core::offchain::IpfsRequestId(1),
			response: Some(IpfsResponse::CatBytes(bytes.clone())),
			..Default::default()
		});
		// disconnect from the external node
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			id: sp_core::offchain::IpfsRequestId(2),
			response: Some(IpfsResponse::Success),
			..Default::default()
		});
		// add bytes to your local node 
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			id: sp_core::offchain::IpfsRequestId(3),
			response: Some(IpfsResponse::AddBytes(cid_vec.clone())),
			..Default::default()
		});
		// get ipfs id
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			id: sp_core::offchain::IpfsRequestId(5),
			response: Some(IpfsResponse::Identity(Vec::new(), Vec::new())),
			..Default::default()
		});
		// insert pin
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			response: Some(IpfsResponse::Success),
			..Default::default()
		});
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			id: sp_core::offchain::IpfsRequestId(5),
			response: Some(IpfsResponse::Identity(Vec::new(), Vec::new())),
			..Default::default()
		});
		// fetch data
		state.expect_ipfs_request(testing::IpfsPendingRequest {
			id: sp_core::offchain::IpfsRequestId(6),
			response: Some(IpfsResponse::CatBytes(bytes.clone())),
			..Default::default()
		});
	}

	t.execute_with(|| {
		assert_ok!(IrisSession::add_validator(Origin::root(), p.clone().public()));
		// WHEN: I invoke the create extrinsic
		// each validator awarded 1 point
		assert_ok!(IrisAssets::create(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			multiaddr_vec.clone(),
			cid_vec.clone(),
			name.clone(),
			dataspace_id.clone(),
			id.clone(),
			balance.clone(),
		));
		// AND: I create an owned asset class
		assert_ok!(IrisSession::submit_ipfs_add_results(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			cid_vec.clone(),
			id.clone(),
			balance.clone(),
			dataspace_id.clone(),
		));
		// AND: I invoke the mint_tickets extrinsic
		assert_ok!(IrisAssets::mint(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			id.clone(),
			balance.clone(),
		));
		// AND: A validator stores the data
		// p is awarded 1 point
		assert_ok!(IrisSession::join_storage_pool(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			id.clone(),
		));
		// AND: I request the owned content from iris
		// p is rewarded 1 point
		assert_ok!(IrisAssets::request_bytes(
			Origin::signed(p.clone().public()),
			id.clone(),
		));
		// THEN: the offchain worker proxies IPFS requests
		assert_ok!(IrisSession::handle_data_requests());
		// AND: Each storage provider receives a reward point
		let mut eras_reward_points = crate::ErasRewardPoints::<Test>::get(0, id.clone()).unwrap();
		assert_eq!(4, eras_reward_points.total);
		for validator in crate::Validators::<Test>::get() {
			assert_eq!(1u32, *eras_reward_points.individual.entry(validator).or_default()	);
		}
	});	
}
