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
use crate::mock::*;
use frame_support::{
	assert_noop, assert_ok, assert_err, bounded_vec, pallet_prelude::*
};
use sp_runtime::{
	testing::UintAuthorityId,
	traits::{Extrinsic as ExtrinsicT},
	RuntimeAppPublic,
};
use sp_core::Pair;
use sp_core::{
	offchain::{testing, OffchainWorkerExt, TransactionPoolExt, OffchainDbExt}
};
use sp_keystore::{testing::KeyStore, KeystoreExt, SyncCryptoStore};
use std::sync::Arc;

use iris_primitives::*;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::SeedableRng,
};
use crypto_box::{
    aead::{ AeadCore, Aead },
	SalsaBox, PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, Nonce,
};

struct TestData {
	pub p: sp_core::sr25519::Pair,
	pub q: sp_core::sr25519::Pair,
	pub plaintext: Vec<u8>,
	pub ciphertext: Vec<u8>,
	pub public_key: Vec<u8>,
	pub data_capsule: Vec<u8>,
	pub nonce: Vec<u8>,
}

thread_local!(static TEST_CONSTANTS: TestData = TestData {
	p: sp_core::sr25519::Pair::generate().0,
	q: sp_core::sr25519::Pair::generate().0,
	ciphertext: "ciphertext".as_bytes().to_vec(),
	plaintext: "plaintext".as_bytes().to_vec(),
	public_key: "public_key".as_bytes().to_vec(),
	data_capsule: "data_capsule".as_bytes().to_vec(),
	nonce: "nonce".as_bytes().to_vec(),
});

#[test]
fn can_submit_encryption_artifacts() {
	TEST_CONSTANTS.with(|t| {
		let pairs = vec![(t.p.clone().public(), 10)];

		// Given: I am a valid node with a positive balance
		let pairs = vec![(t.p.clone().public(), 10)];
		let encrypted_key = EncryptedFragment {
			nonce: t.nonce.clone(),
			ciphertext: t.ciphertext.clone(),
			public_key: t.public_key.clone(),
		};

		new_test_ext_funded(pairs, validators()).execute_with(|| {
			// When: I submit key fragments
			assert_ok!(IrisProxy::submit_encryption_artifacts(
				Origin::signed(t.p.clone().public()),
				t.p.clone().public(),
				t.data_capsule.clone(),
				t.public_key.clone(),
				t.p.clone().public(),
				encrypted_key.clone(),
			));
			// check proxy
			// check proxy codes

			let capsule_data = Capsules::<Test>::get(t.public_key.clone()).unwrap();
			assert_eq!(t.data_capsule.clone(), capsule_data);

			let proxy = Proxy::<Test>::get(t.public_key.clone()).unwrap();
			assert_eq!(t.p.clone().public(), proxy.clone());

			let proxy_code = ProxyCodes::<Test>::get(proxy.clone(), t.public_key.clone()).unwrap();
			assert_eq!(proxy_code, encrypted_key);
		}); 
	});
}

#[test]
fn can_submit_capsule_fragment() {
	TEST_CONSTANTS.with(|t| {
		let pairs = vec![(t.p.clone().public(), 10)];
		let encrypted_capsule_fragment = iris_primitives::EncryptedFragment {
			nonce: t.nonce.clone(),
			ciphertext: t.ciphertext.clone(),
			public_key: t.public_key.clone(),
		};

		new_test_ext_funded(pairs, validators()).execute_with(|| {
			assert_ok!(IrisProxy::submit_capsule_fragment(
				Origin::signed(t.p.clone().public()),
				t.p.clone().public(),
				t.public_key.clone(),
				encrypted_capsule_fragment.clone(),
			));

			let verified_cfrags = VerifiedCapsuleFrags::<Test>::get(
				t.p.clone().public(), t.public_key.clone()
			);
			assert_eq!(verified_cfrags.len(), 1);
			assert_eq!(verified_cfrags[0], encrypted_capsule_fragment.clone());
		});
	});
}

// #[test]
// fn submit_capsule_fragment_fails_if_public_key_unknown() {

// }

// #[test]
// fn can_submit_reencryption_keys() {
// 	TEST_CONSTANTS.with(|t| {

// 	});
// }



#[test]
pub fn offchain_can_encrypt_data_and_submit_artifacts() {
	TEST_CONSTANTS.with(|test_data| {
		let pairs = vec![(test_data.p.clone().public(), 10)];
		let shares = 3;
		let threshold = 2;
		let plaintext = "plaintext".as_bytes();

		let mut rng = ChaCha20Rng::seed_from_u64(31u64);
		let sk = BoxSecretKey::generate(&mut rng);

		let mut t = new_test_ext_funded(pairs, validators());
		let (offchain, state) = testing::TestOffchainExt::new();
		let (pool, pool_state) = testing::TestTransactionPoolExt::new();

		let keystore = KeyStore::new();
		const PHRASE: &str =
			"news slush supreme milk chapter athlete soap sausage put clutch what kitten";
		SyncCryptoStore::sr25519_generate_new(
			&keystore,
			crate::crypto::Public::ID,
			Some(&format!("{}/hunter1", PHRASE)),
		).unwrap();

		t.register_extension(OffchainWorkerExt::new(offchain.clone()));
		t.register_extension(OffchainDbExt::new(offchain.clone()));
		t.register_extension(TransactionPoolExt::new(pool));
		t.register_extension(KeystoreExt(Arc::new(keystore)));

		t.execute_with(|| {
			let ciphertext_bytes = IrisProxy::do_encrypt(
				&test_data.plaintext.clone(),
				5, 3,
				sk.public_key(),
				test_data.p.clone().public(),
				test_data.q.clone().public(),
			);
			let ciphertext = ciphertext_bytes.to_vec();
			assert_eq!(49, ciphertext.len());
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			// unsigned tx
			assert_eq!(tx.signature, None);
			// panic!("{:?}", tx.call);
		});
	});
}

#[test]
fn can_generate_new_kfrags() {
	TEST_CONSTANTS.with(|test_data| {
		let pairs = vec![(test_data.p.clone().public(), 10)];
		let shares = 3;
		let threshold = 2;
		let plaintext = "plaintext".as_bytes();

		let mut rng = ChaCha20Rng::seed_from_u64(31u64);
		let proxy_sk = BoxSecretKey::generate(&mut rng);

		let mut t = new_test_ext_funded(pairs, validators());
		let (offchain, state) = testing::TestOffchainExt::new();
		let (pool, pool_state) = testing::TestTransactionPoolExt::new();

		let keystore = KeyStore::new();
		const PHRASE: &str =
			"news slush supreme milk chapter athlete soap sausage put clutch what kitten";
		SyncCryptoStore::sr25519_generate_new(
			&keystore,
			crate::crypto::Public::ID,
			Some(&format!("{}/hunter1", PHRASE)),
		).unwrap();

		t.register_extension(OffchainWorkerExt::new(offchain.clone()));
		t.register_extension(OffchainDbExt::new(offchain.clone()));
		t.register_extension(TransactionPoolExt::new(pool));
		t.register_extension(KeystoreExt(Arc::new(keystore)));

		t.execute_with(|| {
			// GIVEN: Some data has been encrypted and added to the ingestion staging map
			let ciphertext_bytes = IrisProxy::do_encrypt(
				&test_data.plaintext.clone(),
				5, 3,
				proxy_sk.public_key(),
				test_data.p.clone().public(),
				test_data.q.clone().public(),
			);
			let ciphertext = ciphertext_bytes.to_vec();
			assert_eq!(49, ciphertext.len());
			// AND: I have generated new keys using the authorities pallet
			// assert_ok!(Authorities::create_secrets(
			// 	Origin::signed(test_data.q.public().clone()),
			// ));
			// // THEN: The public key exists in the ingestion staging map
			// let new_public_key = DataAssets::ingestion_staging(test_data.p.clone().public()).unwrap();
			// // WHEN: I simulate a new capsule recovery request for the data
			// IrisProxy::add_capsule_recovery_request(
			// 	test_data.p.clone().public(),
			// 	new_public_key.clone(),
			// );
			// THEN: I can generate new key fragments for the caller

		});
	});
}

fn validators() -> Vec<(sp_core::sr25519::Public, UintAuthorityId)> {
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

	vec![v0.clone(), v1.clone(), v2.clone()]
}
