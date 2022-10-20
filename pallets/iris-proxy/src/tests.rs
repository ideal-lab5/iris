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
	public_key: vec![2, 32, 185, 106, 68, 174, 201, 135, 
		191, 34, 180, 13, 32, 162, 229, 68, 
		52, 118, 248, 52, 201, 84, 117, 230, 
		102, 195, 66, 63, 150, 109, 251, 201, 116],
	data_capsule: vec![
		2, 32, 185, 106, 68, 174, 201, 135, 191, 34, 180, 13, 32, 162, 229, 68, 
		52, 118, 248, 52, 201, 84, 117, 230, 102, 195, 66, 63, 150, 109, 251, 201, 116, 2, 89, 
		58, 239, 98, 206, 136, 245, 46, 28, 176, 136, 190, 229, 179, 147, 164, 153, 86, 198, 7,
		137, 28, 137, 120, 157, 189, 68, 136, 170, 172, 254, 165, 78, 53, 11, 241, 120, 98, 125, 
		85, 195, 102, 189, 101, 178, 203, 154, 20, 212, 66, 209, 247, 220, 56, 248, 19, 23, 41, 
		171, 171, 34, 48, 234, 255],
	nonce: "nonce".as_bytes().to_vec(),
});

#[test]
fn can_submit_encryption_artifacts() {
	TEST_CONSTANTS.with(|test_data| {
		let pairs = vec![(test_data.p.clone().public(), 10)];

		// Given: I am a valid node with a positive balance
		let pairs = vec![(test_data.p.clone().public(), 10)];
		let encrypted_key = EncryptedFragment {
			nonce: test_data.nonce.clone(),
			ciphertext: test_data.ciphertext.clone(),
			public_key: test_data.public_key.clone(),
		};

		new_test_ext_funded(pairs, validators()).execute_with(|| {
			// When: I submit key fragments
			assert_ok!(IrisProxy::submit_encryption_artifacts(
				Origin::signed(test_data.p.clone().public()),
				test_data.p.clone().public(),
				test_data.data_capsule.clone(),
				test_data.public_key.clone(),
				test_data.p.clone().public(),
				encrypted_key.clone(),
			));
			// check proxy
			// check proxy codes

			let capsule_data = Capsules::<Test>::get(test_data.public_key.clone()).unwrap();
			assert_eq!(test_data.data_capsule.clone(), capsule_data);

			let proxy = Proxy::<Test>::get(test_data.public_key.clone()).unwrap();
			assert_eq!(test_data.p.clone().public(), proxy.clone());

			let proxy_code = ProxyCodes::<Test>::get(proxy.clone(), test_data.public_key.clone()).unwrap();
			assert_eq!(proxy_code, encrypted_key);
		}); 
	});
}

#[test]
fn can_submit_capsule_fragment() {
	TEST_CONSTANTS.with(|test_data| {
		let pairs = vec![(test_data.p.clone().public(), 10)];
		let encrypted_capsule_fragment = iris_primitives::EncryptedFragment {
			nonce: test_data.nonce.clone(),
			ciphertext: test_data.ciphertext.clone(),
			public_key: test_data.public_key.clone(),
		};

		new_test_ext_funded(pairs, validators()).execute_with(|| {
			assert_ok!(IrisProxy::submit_capsule_fragment(
				Origin::signed(test_data.p.clone().public()),
				test_data.p.clone().public(),
				test_data.public_key.clone(),
				encrypted_capsule_fragment.clone(),
			));

			let verified_cfrags = VerifiedCapsuleFrags::<Test>::get(
				test_data.p.clone().public(), test_data.public_key.clone()
			);
			assert_eq!(verified_cfrags.len(), 1);
			assert_eq!(verified_cfrags[0], encrypted_capsule_fragment.clone());
		});
	});
}

// // #[test]
// // fn submit_capsule_fragment_fails_if_public_key_unknown() {

// // }

#[test]
fn can_submit_reencryption_keys() {
	TEST_CONSTANTS.with(|test_data| {
		let pairs = vec![(test_data.p.clone().public(), 10)];
		new_test_ext_funded(pairs, validators()).execute_with(|| {
			let frag_0 = EncryptedFragment {
				ciphertext: test_data.ciphertext.clone(),
				public_key: test_data.public_key.clone(),
				nonce: test_data.nonce.clone(),
			};

			let frag_1 = EncryptedFragment {
				ciphertext: test_data.ciphertext.clone(),
				public_key: test_data.public_key.clone(),
				nonce: test_data.nonce.clone(),
			};

			let secret_key_encrypted = EncryptedFragment {
				ciphertext: test_data.ciphertext.clone(),
				public_key: test_data.public_key.clone(),
				nonce: test_data.nonce.clone(),
			};

			let mut kfrag_assignments: Vec<(sp_core::sr25519::Public, EncryptedFragment)> = Vec::new();
			kfrag_assignments.push((test_data.p.clone().public(), frag_0.clone()));
			kfrag_assignments.push((test_data.q.clone().public(), frag_1.clone()));

			assert_ok!(IrisProxy::submit_reencryption_keys(
				Origin::signed(test_data.p.clone().public()),
				test_data.q.clone().public(),
				test_data.public_key.clone(),
				test_data.public_key.clone(),
				kfrag_assignments,
				secret_key_encrypted.clone(),
			));

			// THEN: frag_0 and frag_1 are added to the Fragments map
			let actual_frag_p = crate::Fragments::<Test>::get((
				test_data.q.clone().public(), 
				test_data.public_key.clone(), 
				test_data.p.clone().public(),
			));
			let actual_frag_q = crate::Fragments::<Test>::get((
				test_data.q.clone().public(), 
				test_data.public_key.clone(), 
				test_data.q.clone().public(),
			));

			assert_eq!(Some(frag_0.clone()), actual_frag_p);
			assert_eq!(Some(frag_1.clone()), actual_frag_q);


			// AND: Reencryption requests are added
			let reencryption_req_p = crate::ReencryptionRequests::<Test>::get(
				test_data.p.clone().public()
			);
			let reencryption_req_q = crate::ReencryptionRequests::<Test>::get(
				test_data.q.clone().public()
			);

			assert_eq!(1, reencryption_req_p.len());
			assert_eq!(1, reencryption_req_q.len());

			assert_eq!(reencryption_req_p[0].caller, test_data.q.clone().public());
			assert_eq!(reencryption_req_p[0].data_public_key, test_data.public_key.clone());
			assert_eq!(reencryption_req_p[0], reencryption_req_q[0]);

			let e_key = crate::EphemeralKeys::<Test>::get(
				test_data.q.clone().public(), 
				test_data.public_key.clone()
			);
			assert_eq!(test_data.public_key.clone(), e_key);

			let s_key = crate::SecretKeys::<Test>::get(
				test_data.q.clone().public(), 
				test_data.public_key.clone()
			).unwrap();
			assert_eq!(secret_key_encrypted.clone(), s_key);

			let actual_frag_owners = crate::FragmentOwnerSet::<Test>::get(
				test_data.q.clone().public(), 
				test_data.public_key.clone()
			);
			assert_eq!(2, actual_frag_owners.len());
		});
	});
}
/*
	OFFCHAIN 
*/
#[test]
pub fn offchain_can_encrypt_data_and_submit_artifacts() {
	TEST_CONSTANTS.with(|test_data| {
		let pairs = vec![(test_data.p.clone().public(), 10)];
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

			let sk_box = EncryptedFragment {
				nonce: vec![102, 209, 34, 179, 214, 75, 129,  24, 
							44, 14, 136, 104, 179, 34, 247, 161, 
							168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![76, 236, 32, 60, 161, 53, 11, 169, 11, 
							92, 15, 188, 173, 102, 6, 17, 88, 25, 228, 
							208, 149, 25, 5, 184, 97, 54, 40, 59, 237, 
							87, 50, 173, 62, 1, 200, 115, 87, 11, 160, 
							134, 139, 103, 194, 59, 123, 34, 227, 15], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 
							185, 24, 43, 243, 37, 77, 126,  183, 
							5, 114, 157, 167, 133, 183, 81, 29, 
							217, 53, 237, 240, 233, 111, 29, 9, 84] 
			};

			let submit_encryption_artifacts_call = mock::Call::IrisProxy(Call::submit_encryption_artifacts { 
				owner: test_data.p.clone().public(), 
				data_capsule: test_data.data_capsule.clone(), 
				public_key: test_data.public_key.clone(), 
				proxy: test_data.q.clone().public(), 
				sk_encryption_info: sk_box.clone(),
			});


			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			// unsigned tx
			assert_eq!(tx.signature, None);
			assert_eq!(submit_encryption_artifacts_call, tx.call);
		});
	});
}

#[test]
fn can_process_kfrag_generation_request() {
	TEST_CONSTANTS.with(|test_data| {
		let pairs = vec![(test_data.p.clone().public(), 10)];
		let plaintext = "plaintext".as_bytes();

		let mut rng = ChaCha20Rng::seed_from_u64(31u64);
		let proxy_sk = BoxSecretKey::generate(&mut rng);

		let validators = validators();
		let mut t = new_test_ext_funded(pairs, validators.clone());
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

			let sk_box = EncryptedFragment {
				nonce: vec![102, 209, 34, 179, 214, 75, 129,  24, 
							44, 14, 136, 104, 179, 34, 247, 161, 
							168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![76, 236, 32, 60, 161, 53, 11, 169, 
							11, 92, 15, 188, 173, 102, 6, 17, 88, 25, 
							228, 208, 149, 25, 5, 184, 97, 54, 40, 59, 237, 
							87, 50, 173, 62, 1, 200, 115, 87, 11, 160, 134, 
							139, 103, 194, 59, 123, 34, 227, 15], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 
							185, 24, 43, 243, 37, 77, 126,  183, 
							5, 114, 157, 167, 133, 183, 81, 29, 
							217, 53, 237, 240, 233, 111, 29, 9, 84] 
			};

			let submit_encryption_artifacts_call = mock::Call::IrisProxy(Call::submit_encryption_artifacts { 
				owner: test_data.p.clone().public(), 
				data_capsule: test_data.data_capsule.clone(), 
				public_key: test_data.public_key.clone(), 
				proxy: test_data.q.clone().public(), 
				sk_encryption_info: sk_box.clone(),
			});

			// GIVEN: Some data has been encrypted and added to the ingestion staging map
			IrisProxy::do_encrypt(
				&test_data.plaintext.clone(),
				5, 3,
				proxy_sk.public_key(),
				test_data.p.clone().public(), // owner
				test_data.q.clone().public(), // proxy
			);
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature, None);
			assert_eq!(submit_encryption_artifacts_call, tx.call);

			// now we want to simulate the extrinsic being executed
			assert_ok!(IrisProxy::submit_encryption_artifacts(
				Origin::signed(test_data.p.clone().public()), 
				test_data.p.clone().public(),  // owner
				test_data.data_capsule.clone(), // capsule
				test_data.public_key.clone(), // umbral pk
				test_data.q.clone().public(), // proxy
				sk_box.clone(), // encrypted sk to decrypt umbral sk 
			));
			// AND: I each validator has generated new keys using the authorities pallet
			assert_ok!(Authorities::create_secrets(
				Origin::signed(test_data.q.public().clone()),
			));
			assert_ok!(Authorities::create_secrets(
				Origin::signed(test_data.p.public().clone()),
			));
			for v in validators.clone() {
				assert_ok!(Authorities::create_secrets(
					Origin::signed(v.0.clone())
				));
				assert_eq!(32, Authorities::x25519_public_keys(v.0.clone()).len());
			}

			// THEN: The public key exists in the ingestion staging map
			// let new_public_key = DataAssets::ingestion_staging(test_data.p.clone().public()).unwrap();
			// WHEN: I simulate a new capsule recovery request for the data
			IrisProxy::add_capsule_recovery_request(
				test_data.p.clone().public(),
				test_data.public_key.clone(),
			);


			let sk = EncryptedFragment { 
				nonce: vec![102, 209, 34, 179, 214, 75, 129, 
					24, 44, 14, 136, 104, 179, 34, 247, 161, 
					168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![180, 87, 48, 1, 209, 111, 
					101, 30, 115, 115, 64, 113, 43, 108, 219, 
					186, 63, 220, 233, 211, 233, 22, 233, 194, 
					162, 78, 27, 145, 61, 74, 115, 8, 95, 
					43, 218, 32, 103, 70, 248, 182, 4, 134, 
					130, 225, 9, 196, 154, 92], 
				public_key: vec![136, 127, 175, 150, 142, 160, 
					194, 185, 24, 43, 243, 37, 77, 126, 183, 
					5, 114, 157, 167, 133, 183, 81, 29, 
					217, 53, 237, 240, 233, 111, 29, 9, 84] 
			};

			let ephemeral_pk_vec = vec![
				2, 74, 50, 75, 57, 138, 197, 
				248, 204, 201, 125, 87, 177, 81, 
				222, 20, 49, 128, 38, 251, 104, 
				211, 77, 79, 11, 140, 181, 7, 
				9, 76, 209, 226, 215
			];

			let frag_0 = EncryptedFragment { 
				nonce: vec![102, 209, 34, 179, 214, 75, 
					129, 24, 44, 14, 136, 104, 179, 34, 247, 
					161, 168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![59, 237, 216, 176, 20, 240, 10, 101, 162, 99, 81, 84, 138, 83, 
					71, 172, 110, 64, 182, 195, 221, 102, 137, 247, 7, 175, 162, 0, 223, 168, 
					131, 213, 195, 121, 66, 84, 139, 128, 185, 184, 183, 166, 123, 51, 176, 117,
					 41, 216, 138, 141, 43, 158, 35, 237, 204, 219, 153, 181, 73, 183, 14, 180, 
					 249, 93, 35, 247, 17, 104, 252, 12, 190, 142, 208, 109, 8, 193, 184, 143, 
					 189, 11, 201, 188, 222, 72, 49, 120, 72, 123, 202, 155, 130, 205, 169, 52, 
					 62, 211, 32, 214, 130, 119, 162, 250, 185, 57, 108, 122, 227, 244, 50, 9, 
					 223, 164, 112, 144, 179, 134, 142, 223, 32, 114, 127, 165, 215, 229, 142, 
					 177, 201, 244, 245, 175, 17, 167, 58, 227, 91, 18, 201, 40, 219, 231, 124, 
					 130, 62, 125, 163, 61, 123, 66, 4, 219, 38, 133, 203, 234, 82, 138, 154, 69, 
					 199, 72, 16, 146, 230, 149, 75, 147, 138, 46, 210, 158, 55, 137, 228, 246, 90,
					  99, 3, 152, 55, 69, 30, 101, 253, 233, 56, 245, 62, 30, 172, 244, 205, 111, 
					  35, 83, 10, 133, 107, 7, 72, 37, 101, 220, 184, 175, 38, 11, 128, 240, 23,
					   222, 100, 137, 132, 172, 212, 8, 184, 177, 137, 201, 11, 155, 101, 187, 25,
					190, 148, 91, 43, 225, 8, 145, 45, 105, 207, 236, 126, 217, 55, 54, 160, 
					147, 13, 136, 3, 214, 232, 60, 159, 240, 192, 44, 144, 237, 95, 49, 229, 
					219, 54, 21, 52, 41, 255, 227, 96, 27, 12, 163, 210, 192, 62, 213, 131, 13, 246, 96], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 5, 
					114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84]
			};

			let frag_1 = EncryptedFragment { 
				nonce: vec![102, 209, 34, 179, 214, 75, 129, 24, 44, 14, 136, 104, 179, 34, 
					247, 161, 168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![14, 242, 31, 22, 127, 184, 158, 215, 12, 183, 233, 184, 114, 
					162, 233, 86, 112, 12, 129, 219, 55, 252, 115, 88, 155, 236, 165, 48, 99, 
					217, 120, 125, 237, 93, 177, 146, 15, 191, 246, 132, 181, 84, 234, 101, 
					114, 207, 177, 62, 235, 253, 176, 207, 192, 193, 252, 67, 9, 230, 106, 
					115, 170, 148, 6, 199, 28, 117, 17, 40, 17, 8, 1, 103, 110, 177, 22, 40,
					138, 39, 166, 4, 201, 188, 222, 72, 49, 120, 72, 123, 202, 155, 130, 
					205, 169, 52, 62, 211, 32, 214, 130, 119, 162, 250, 185, 57, 108, 122,
					227, 244, 50, 9, 223, 164, 112, 145, 150, 167, 12, 59, 195, 75, 178, 
					31, 40, 54, 207, 45, 223, 33, 229, 45, 3, 61, 141, 163, 30, 102, 169, 
					185, 237, 91, 93, 215, 152, 95, 211, 242, 80, 237, 136, 130, 33, 51, 
					126, 3, 249, 99, 154, 218, 155, 161, 50, 129, 29, 3, 231, 44, 211, 252, 
					238, 111, 172, 147, 98, 128, 189, 202, 76, 77, 115, 125, 164, 252, 
					211, 144, 78, 164, 169, 82, 236, 20, 18, 233, 139, 7, 208, 147, 4, 
					137, 36, 39, 50, 150, 94, 50, 154, 31, 249, 79, 215, 52, 135, 17, 200, 
					137, 16, 174, 21, 151, 200, 220, 98, 240, 92, 207, 34, 49, 242, 105, 226, 
					230, 1, 22, 253, 120, 64, 226, 172, 149, 41, 121, 81, 138, 13, 255, 155, 
					1, 57, 154, 230, 234, 156, 87, 184, 233, 132, 97, 224, 184, 117, 91, 169, 
					185, 244, 223, 247, 186, 26, 243, 64, 114, 183, 95, 218, 225, 246, 96], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 
					5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84] 
			};

			let call = mock::Call::IrisProxy(Call::submit_reencryption_keys 
				{ 
					consumer: test_data.p.clone().public(), 
					ephemeral_public_key: ephemeral_pk_vec.clone(), 
					data_public_key: vec![2, 32, 185, 106, 68, 174, 201, 135, 
						191, 34, 180, 13, 32, 162, 229, 
						68, 52, 118, 248, 52, 201, 84, 
						117, 230, 102, 195, 66, 63, 
						150, 109, 251, 201, 116], 
					kfrag_assignments: vec![
						(validators[0].clone().0, frag_0.clone()), 
						(validators[2].clone().0, frag_1.clone())
					],
					encrypted_sk_box: sk.clone(),
				}
			);

			// THEN: I can generate new key fragments for the caller
			assert_ok!(IrisProxy::proxy_process_kfrag_generation_requests(
				test_data.q.clone().public(),
				validators.clone().iter()
					.map(|v| (
						v.0,
						proxy_sk.public_key().clone().as_bytes().to_vec()
					)).collect::<Vec<_>>()
			));
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature.unwrap().0, 0);
			assert_eq!(call, tx.call);
			// Then: When the extrinsic is executed
			assert_ok!(IrisProxy::submit_reencryption_keys(
				Origin::signed(test_data.q.clone().public()),
				test_data.q.clone().public(),
				ephemeral_pk_vec.clone(),
				test_data.public_key.clone(),
				vec![(validators[0].clone().0, frag_0.clone()), 
					 (validators[1].clone().0, frag_1.clone())],
				sk.clone(),
			));
		});
	});
}

#[test]
fn can_process_reencryption_request() {
	TEST_CONSTANTS.with(|test_data| {
		let pairs = vec![(test_data.p.clone().public(), 10)];
		let plaintext = "plaintext".as_bytes();

		let mut rng = ChaCha20Rng::seed_from_u64(31u64);
		let proxy_sk = BoxSecretKey::generate(&mut rng);

		let validators = validators();
		let mut t = new_test_ext_funded(pairs, validators.clone());
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

			let sk_box = EncryptedFragment {
				nonce: vec![102, 209, 34, 179, 214, 75, 129,  24, 
							44, 14, 136, 104, 179, 34, 247, 161, 
							168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![76, 236, 32, 60, 161, 53, 11, 169, 
							11, 92, 15, 188, 173, 102, 6, 17, 88, 25, 
							228, 208, 149, 25, 5, 184, 97, 54, 40, 59, 237, 
							87, 50, 173, 62, 1, 200, 115, 87, 11, 160, 134, 
							139, 103, 194, 59, 123, 34, 227, 15], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 
							185, 24, 43, 243, 37, 77, 126,  183, 
							5, 114, 157, 167, 133, 183, 81, 29, 
							217, 53, 237, 240, 233, 111, 29, 9, 84] 
			};

			let submit_encryption_artifacts_call = mock::Call::IrisProxy(Call::submit_encryption_artifacts { 
				owner: test_data.p.clone().public(), 
				data_capsule: test_data.data_capsule.clone(), 
				public_key: test_data.public_key.clone(), 
				proxy: test_data.q.clone().public(), 
				sk_encryption_info: sk_box.clone(),
			});

			// GIVEN: Some data has been encrypted and added to the ingestion staging map
			IrisProxy::do_encrypt(
				&test_data.plaintext.clone(),
				5, 3,
				proxy_sk.public_key(),
				test_data.p.clone().public(), // owner
				test_data.q.clone().public(), // proxy
			);
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature, None);
			assert_eq!(submit_encryption_artifacts_call, tx.call);

			// now we want to simulate the extrinsic being executed
			assert_ok!(IrisProxy::submit_encryption_artifacts(
				Origin::signed(test_data.p.clone().public()), 
				test_data.p.clone().public(),  // owner
				test_data.data_capsule.clone(), // capsule
				test_data.public_key.clone(), // umbral pk
				test_data.q.clone().public(), // proxy
				sk_box.clone(), // encrypted sk to decrypt umbral sk 
			));
			// AND: I each validator has generated new keys using the authorities pallet
			assert_ok!(Authorities::create_secrets(
				Origin::signed(test_data.q.public().clone()),
			));
			assert_ok!(Authorities::create_secrets(
				Origin::signed(test_data.p.public().clone()),
			));
			for v in validators.clone() {
				assert_ok!(Authorities::create_secrets(
					Origin::signed(v.0.clone())
				));
				assert_eq!(32, Authorities::x25519_public_keys(v.0.clone()).len());
			}

			// THEN: The public key exists in the ingestion staging map
			// let new_public_key = DataAssets::ingestion_staging(test_data.p.clone().public()).unwrap();
			// WHEN: I simulate a new capsule recovery request for the data
			IrisProxy::add_capsule_recovery_request(
				test_data.p.clone().public(),
				test_data.public_key.clone(),
			);


			let sk = EncryptedFragment { 
				nonce: vec![102, 209, 34, 179, 214, 75, 129, 
					24, 44, 14, 136, 104, 179, 34, 247, 161, 
					168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![180, 87, 48, 1, 209, 111, 
					101, 30, 115, 115, 64, 113, 43, 108, 219, 
					186, 63, 220, 233, 211, 233, 22, 233, 194, 
					162, 78, 27, 145, 61, 74, 115, 8, 95, 
					43, 218, 32, 103, 70, 248, 182, 4, 134, 
					130, 225, 9, 196, 154, 92], 
				public_key: vec![136, 127, 175, 150, 142, 160, 
					194, 185, 24, 43, 243, 37, 77, 126, 183, 
					5, 114, 157, 167, 133, 183, 81, 29, 
					217, 53, 237, 240, 233, 111, 29, 9, 84] 
			};

			let ephemeral_pk_vec = vec![
				2, 74, 50, 75, 57, 138, 197, 
				248, 204, 201, 125, 87, 177, 81, 
				222, 20, 49, 128, 38, 251, 104, 
				211, 77, 79, 11, 140, 181, 7, 
				9, 76, 209, 226, 215
			];

			let frag_0 = EncryptedFragment { 
				nonce: vec![102, 209, 34, 179, 214, 75, 
					129, 24, 44, 14, 136, 104, 179, 34, 247, 
					161, 168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![59, 237, 216, 176, 20, 240, 10, 101, 162, 99, 81, 84, 138, 83, 
					71, 172, 110, 64, 182, 195, 221, 102, 137, 247, 7, 175, 162, 0, 223, 168, 
					131, 213, 195, 121, 66, 84, 139, 128, 185, 184, 183, 166, 123, 51, 176, 117,
					 41, 216, 138, 141, 43, 158, 35, 237, 204, 219, 153, 181, 73, 183, 14, 180, 
					 249, 93, 35, 247, 17, 104, 252, 12, 190, 142, 208, 109, 8, 193, 184, 143, 
					 189, 11, 201, 188, 222, 72, 49, 120, 72, 123, 202, 155, 130, 205, 169, 52, 
					 62, 211, 32, 214, 130, 119, 162, 250, 185, 57, 108, 122, 227, 244, 50, 9, 
					 223, 164, 112, 144, 179, 134, 142, 223, 32, 114, 127, 165, 215, 229, 142, 
					 177, 201, 244, 245, 175, 17, 167, 58, 227, 91, 18, 201, 40, 219, 231, 124, 
					 130, 62, 125, 163, 61, 123, 66, 4, 219, 38, 133, 203, 234, 82, 138, 154, 69, 
					 199, 72, 16, 146, 230, 149, 75, 147, 138, 46, 210, 158, 55, 137, 228, 246, 90,
					  99, 3, 152, 55, 69, 30, 101, 253, 233, 56, 245, 62, 30, 172, 244, 205, 111, 
					  35, 83, 10, 133, 107, 7, 72, 37, 101, 220, 184, 175, 38, 11, 128, 240, 23,
					   222, 100, 137, 132, 172, 212, 8, 184, 177, 137, 201, 11, 155, 101, 187, 25,
					190, 148, 91, 43, 225, 8, 145, 45, 105, 207, 236, 126, 217, 55, 54, 160, 
					147, 13, 136, 3, 214, 232, 60, 159, 240, 192, 44, 144, 237, 95, 49, 229, 
					219, 54, 21, 52, 41, 255, 227, 96, 27, 12, 163, 210, 192, 62, 213, 131, 13, 246, 96], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 
					126, 183, 5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84]
			};

			let frag_1 = EncryptedFragment { 
				nonce: vec![102, 209, 34, 179, 214, 75, 129, 24, 44, 14, 136, 104, 179, 34, 
					247, 161, 168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![14, 242, 31, 22, 127, 184, 158, 215, 12, 183, 233, 184, 114, 
					162, 233, 86, 112, 12, 129, 219, 55, 252, 115, 88, 155, 236, 165, 48, 99, 
					217, 120, 125, 237, 93, 177, 146, 15, 191, 246, 132, 181, 84, 234, 101, 
					114, 207, 177, 62, 235, 253, 176, 207, 192, 193, 252, 67, 9, 230, 106, 
					115, 170, 148, 6, 199, 28, 117, 17, 40, 17, 8, 1, 103, 110, 177, 22, 40,
					138, 39, 166, 4, 201, 188, 222, 72, 49, 120, 72, 123, 202, 155, 130, 
					205, 169, 52, 62, 211, 32, 214, 130, 119, 162, 250, 185, 57, 108, 122,
					227, 244, 50, 9, 223, 164, 112, 145, 150, 167, 12, 59, 195, 75, 178, 
					31, 40, 54, 207, 45, 223, 33, 229, 45, 3, 61, 141, 163, 30, 102, 169, 
					185, 237, 91, 93, 215, 152, 95, 211, 242, 80, 237, 136, 130, 33, 51, 
					126, 3, 249, 99, 154, 218, 155, 161, 50, 129, 29, 3, 231, 44, 211, 252, 
					238, 111, 172, 147, 98, 128, 189, 202, 76, 77, 115, 125, 164, 252, 
					211, 144, 78, 164, 169, 82, 236, 20, 18, 233, 139, 7, 208, 147, 4, 
					137, 36, 39, 50, 150, 94, 50, 154, 31, 249, 79, 215, 52, 135, 17, 200, 
					137, 16, 174, 21, 151, 200, 220, 98, 240, 92, 207, 34, 49, 242, 105, 226, 
					230, 1, 22, 253, 120, 64, 226, 172, 149, 41, 121, 81, 138, 13, 255, 155, 
					1, 57, 154, 230, 234, 156, 87, 184, 233, 132, 97, 224, 184, 117, 91, 169, 
					185, 244, 223, 247, 186, 26, 243, 64, 114, 183, 95, 218, 225, 246, 96], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 
					5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84] 
			};

			let call = mock::Call::IrisProxy(Call::submit_reencryption_keys 
				{ 
					consumer: test_data.p.clone().public(), 
					ephemeral_public_key: ephemeral_pk_vec.clone(), 
					data_public_key: vec![2, 32, 185, 106, 68, 174, 201, 135, 
						191, 34, 180, 13, 32, 162, 229, 
						68, 52, 118, 248, 52, 201, 84, 
						117, 230, 102, 195, 66, 63, 
						150, 109, 251, 201, 116], 
					kfrag_assignments: vec![
						(validators[0].clone().0, frag_0.clone()), 
						(validators[2].clone().0, frag_1.clone())
					],
					encrypted_sk_box: sk.clone(),
				}
			);

			// THEN: I can generate new key fragments for the caller
			assert_ok!(IrisProxy::proxy_process_kfrag_generation_requests(
				test_data.q.clone().public(),
				validators.clone().iter()
					.map(|v| (
						v.0,
						proxy_sk.public_key().clone().as_bytes().to_vec()
					)).collect::<Vec<_>>()
			));
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature.unwrap().0, 0);
			assert_eq!(call, tx.call);
			// WHEN: the extrinsic is executed
			assert_ok!(IrisProxy::submit_reencryption_keys(
				Origin::signed(test_data.q.clone().public()),
				test_data.q.clone().public(),
				ephemeral_pk_vec.clone(),
				test_data.public_key.clone(),
				vec![(validators[0].clone().0, frag_0.clone()), 
					 (validators[1].clone().0, frag_1.clone())],
				sk.clone(),
			));

			// let reencryption_req_p = crate::ReencryptionRequests::<Test>::get(
			// 	validators[0].clone().0
			// );

			// AND: I process reencryption requests
			assert_ok!(IrisProxy::kfrag_holder_process_reencryption_requests(
				validators[0].clone().0,
			));

			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature.unwrap().0, 0);
			// assert_eq!(call, tx.call);
		});
	});
}

// #[test]
// fn add_capsule_recovery_request_fails_if_no_proxy_for_public_key() {

// }

// TODO: move this into TEST_DATA
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
