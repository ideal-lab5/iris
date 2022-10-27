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
	pub r: sp_core::sr25519::Pair,
	pub plaintext: Vec<u8>,
	pub ciphertext: Vec<u8>,
	pub public_key: Vec<u8>,
	pub capsule: Vec<u8>,
	pub nonce: Vec<u8>,
}

thread_local!(static TEST_CONSTANTS: TestData = TestData {
	p: sp_core::sr25519::Pair::generate().0,
	q: sp_core::sr25519::Pair::generate().0,
	r: sp_core::sr25519::Pair::generate().0,
	ciphertext: "ciphertext".as_bytes().to_vec(),
	plaintext: "plaintext".as_bytes().to_vec(),
	public_key: vec![2, 32, 185, 106, 68, 174, 201, 135, 
		191, 34, 180, 13, 32, 162, 229, 68, 
		52, 118, 248, 52, 201, 84, 117, 230, 
		102, 195, 66, 63, 150, 109, 251, 201, 116],
	capsule: vec![
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
		let encrypted_key = EncryptedBox {
			nonce: test_data.nonce.clone(),
			ciphertext: test_data.ciphertext.clone(),
			public_key: test_data.public_key.clone(),
		};

		new_test_ext_funded(pairs, validators()).execute_with(|| {
			// When: I submit key fragments
			assert_ok!(IrisProxy::submit_encryption_artifacts(
				Origin::signed(test_data.p.clone().public()),
				test_data.p.clone().public(),
				test_data.p.clone().public(),
				test_data.capsule.clone(),
				test_data.public_key.clone(),
				encrypted_key.clone(),
			));
			// check proxy
			// check proxy codes

			let capsule_data = Capsules::<Test>::get(test_data.public_key.clone()).unwrap();
			assert_eq!(test_data.capsule.clone(), capsule_data);

			let proxy = EncryptionArtifacts::<Test>::get(test_data.public_key.clone()).unwrap().proxy.clone();
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
		let encrypted_capsule_fragment = iris_primitives::EncryptedBox {
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

			let verified_cfrags = EncryptedCapsuleFrags::<Test>::get(
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
			let frag_0 = EncryptedBox {
				ciphertext: test_data.ciphertext.clone(),
				public_key: test_data.public_key.clone(),
				nonce: test_data.nonce.clone(),
			};

			let frag_1 = EncryptedBox {
				ciphertext: test_data.ciphertext.clone(),
				public_key: test_data.public_key.clone(),
				nonce: test_data.nonce.clone(),
			};

			let secret_key_encrypted = EncryptedBox {
				ciphertext: test_data.ciphertext.clone(),
				public_key: test_data.public_key.clone(),
				nonce: test_data.nonce.clone(),
			};

			let mut kfrag_assignments: Vec<(sp_core::sr25519::Public, EncryptedBox)> = Vec::new();
			kfrag_assignments.push((test_data.p.clone().public(), frag_0.clone()));
			kfrag_assignments.push((test_data.q.clone().public(), frag_1.clone()));

			assert_ok!(IrisProxy::submit_reencryption_keys(
				Origin::signed(test_data.p.clone().public()),
				test_data.q.clone().public(),
				test_data.public_key.clone(),
				test_data.public_key.clone(),
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

			// let actual_frag_owners = crate::FragmentOwnerSet::<Test>::get(
			// 	test_data.q.clone().public(), 
			// 	test_data.public_key.clone()
			// );
			// assert_eq!(2, actual_frag_owners.len());
		});
	});
}
// /*
// 	OFFCHAIN 
// */
// #[test]
// pub fn offchain_can_encrypt_data_and_submit_artifacts() {
// 	TEST_CONSTANTS.with(|test_data| {
// 		let pairs = vec![(test_data.p.clone().public(), 10)];

// 		let mut rng = ChaCha20Rng::seed_from_u64(31u64);
// 		let sk = BoxSecretKey::generate(&mut rng);

// 		let mut t = new_test_ext_funded(pairs, validators());
// 		let (offchain, state) = testing::TestOffchainExt::new();
// 		let (pool, pool_state) = testing::TestTransactionPoolExt::new();

// 		let keystore = KeyStore::new();
// 		const PHRASE: &str =
// 			"news slush supreme milk chapter athlete soap sausage put clutch what kitten";
// 		SyncCryptoStore::sr25519_generate_new(
// 			&keystore,
// 			crate::crypto::Public::ID,
// 			Some(&format!("{}/hunter1", PHRASE)),
// 		).unwrap();

// 		t.register_extension(OffchainWorkerExt::new(offchain.clone()));
// 		t.register_extension(OffchainDbExt::new(offchain.clone()));
// 		t.register_extension(TransactionPoolExt::new(pool));
// 		t.register_extension(KeystoreExt(Arc::new(keystore)));

// 		t.execute_with(|| {
// 			let ciphertext_bytes = IrisProxy::do_encrypt(
// 				&test_data.plaintext.clone(),
// 				test_data.p.clone().public(),
// 				test_data.q.clone().public(),
// 			);
// 			let ciphertext = ciphertext_bytes.to_vec();
// 			assert_eq!(49, ciphertext.len());

// 			let sk_box = EncryptedBox {
// 				nonce: vec![102, 209, 34, 179, 214, 75, 129,  24, 
// 							44, 14, 136, 104, 179, 34, 247, 161, 
// 							168, 16, 131, 113, 43, 29, 165, 49], 
// 				ciphertext: vec![76, 236, 32, 60, 161, 53, 11, 169, 11, 
// 							92, 15, 188, 173, 102, 6, 17, 88, 25, 228, 
// 							208, 149, 25, 5, 184, 97, 54, 40, 59, 237, 
// 							87, 50, 173, 62, 1, 200, 115, 87, 11, 160, 
// 							134, 139, 103, 194, 59, 123, 34, 227, 15], 
// 				public_key: vec![136, 127, 175, 150, 142, 160, 194, 
// 							185, 24, 43, 243, 37, 77, 126,  183, 
// 							5, 114, 157, 167, 133, 183, 81, 29, 
// 							217, 53, 237, 240, 233, 111, 29, 9, 84] 
// 			};

// 			let submit_encryption_artifacts_call = mock::Call::IrisProxy(Call::submit_encryption_artifacts { 
// 				owner: test_data.p.clone().public(), 
// 				capsule: test_data.capsule.clone(), 
// 				public_key: test_data.public_key.clone(), 
// 				proxy: test_data.q.clone().public(), 
// 				sk_encryption_info: sk_box.clone(),
// 			});


// 			let tx = pool_state.write().transactions.pop().unwrap();
// 			assert!(pool_state.read().transactions.is_empty());
// 			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
// 			// unsigned tx
// 			assert_eq!(tx.signature, None);
// 			assert_eq!(submit_encryption_artifacts_call, tx.call);
// 		});
// 	});
// }

#[test]
fn can_process_kfrag_generation_request() {
	TEST_CONSTANTS.with(|test_data| {
		let owner = test_data.p.clone();
		let proxy = test_data.q.clone();
		let consumer = test_data.r.clone();

		let pairs = vec![
			(owner.clone().public(), 10),
			(consumer.clone().public(), 10),
			(proxy.clone().public(), 10)
		];

		let mut rng = ChaCha20Rng::seed_from_u64(31u64);

		// this is the new ephemeral keypair created by consumer 
		let consumer_sk = BoxSecretKey::generate(&mut rng);
		let consumer_box_pk = consumer_sk.public_key();

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

			// Given: validator and proxies have generated secrets
			assert_ok!(Authorities::create_secrets(
				Origin::signed(owner.public().clone()),
			));
			assert_ok!(Authorities::create_secrets(
				Origin::signed(proxy.public().clone()),
			));
			for v in validators.clone() {
				assert_ok!(Authorities::create_secrets(
					Origin::signed(v.0.clone())
				));
			}

			let sk_box = EncryptedBox {
				nonce: vec![102, 209, 34, 179, 214, 75, 129,  24, 
							44, 14, 136, 104, 179, 34, 247, 161, 
							168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![76, 236, 32, 60, 161, 53, 11, 169, 11, 92, 15, 188, 173, 102, 6, 17, 88, 25, 228, 208, 149, 25, 5, 184, 97, 54, 40, 59, 237, 87, 50, 173, 62, 1, 200, 115, 87, 11, 160, 134, 139, 103, 194, 59, 123, 34, 227, 15], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 
							185, 24, 43, 243, 37, 77, 126,  183, 
							5, 114, 157, 167, 133, 183, 81, 29, 
							217, 53, 237, 240, 233, 111, 29, 9, 84] 
			};

			let submit_encryption_artifacts_call = mock::Call::IrisProxy(Call::submit_encryption_artifacts { 
				owner: owner.clone().public(), 
				capsule: test_data.capsule.clone(), 
				public_key: test_data.public_key.clone(), 
				proxy: proxy.clone().public(), 
				encrypted_sk_box: sk_box.clone(),
			});

			let proxy_pk_bytes = Authorities ::x25519_public_keys(proxy.public().clone());
			let proxy_pk = vec_to_box_public_key(&proxy_pk_bytes);

			// GIVEN: Some data has been encrypted and added to the ingestion staging map
			let ciphertext_bytes = IrisProxy::do_encrypt(
				&test_data.plaintext.clone(),
				owner.clone().public(), // owner
				proxy.clone().public(), // proxy
			);
			
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature, None);
			assert_eq!(submit_encryption_artifacts_call, tx.call);


			/*
				Kind of signifies 'end of part one'
			*/


			// now we want to simulate the extrinsic being executed
			assert_ok!(IrisProxy::submit_encryption_artifacts(
				Origin::signed(owner.clone().public()), 
				owner.clone().public(),  // owner
				proxy.clone().public(), // proxy
				test_data.capsule.clone(), // capsule 
				test_data.public_key.clone(), // umbral pk
				sk_box.clone(), // encrypted sk to decrypt umbral sk 
			));

			// THEN: The public key exists in the ingestion staging map
			// let new_public_key = DataAssets::ingestion_staging(test_data.p.clone().public()).unwrap();
			// WHEN: I simulate a new capsule recovery request for the data
			IrisProxy::add_kfrag_request(
				consumer.clone().public(),
				test_data.public_key.clone(),
				consumer_box_pk.as_bytes().to_vec().clone(),
			);

			let sk = EncryptedBox { 
				nonce: vec![102, 209, 34, 179, 214, 75, 129, 
					24, 44, 14, 136, 104, 179, 34, 247, 161, 
					168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![219, 140, 164, 182, 194, 125, 129, 157, 29, 37, 228, 22, 170, 32, 105, 162, 248, 245, 156, 187, 107, 237, 70, 78, 154, 125, 13, 223, 27, 213, 129, 103, 190, 3, 28, 75, 213, 140, 88, 7, 187, 101, 243, 146, 172, 11, 234, 31], 
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

			let frag_0 = EncryptedBox { 
				nonce: vec![102, 209, 34, 179, 214, 75, 
					129, 24, 44, 14, 136, 104, 179, 34, 247, 
					161, 168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![77, 44, 174, 139, 113, 253, 132, 254, 0, 152, 44, 45, 18, 40, 139, 120, 85, 230, 45, 38, 32, 131, 98, 47, 117, 199, 210, 149, 224, 6, 237, 179, 76, 113, 98, 251, 27, 159, 84, 102, 161, 36, 218, 98, 71, 176, 28, 157, 80, 206, 86, 9, 82, 190, 211, 66, 223, 148, 183, 45, 237, 119, 229, 165, 253, 133, 170, 185, 166, 87, 167, 156, 242, 189, 35, 61, 130, 59, 6, 53, 201, 188, 222, 72, 49, 120, 72, 123, 202, 155, 130, 205, 169, 52, 62, 211, 32, 214, 130, 119, 162, 250, 185, 57, 108, 122, 227, 244, 50, 9, 223, 164, 112, 145, 204, 30, 171, 254, 96, 165, 32, 196, 142, 176, 121, 81, 171, 187, 228, 110, 206, 248, 115, 32, 162, 76, 136, 99, 53, 92, 92, 102, 241, 193, 39, 181, 106, 68, 116, 146, 242, 239, 82, 245, 198, 176, 219, 104, 220, 7, 171, 85, 251, 170, 5, 255, 97, 73, 248, 138, 201, 69, 183, 217, 172, 108, 78, 20, 10, 72, 240, 113, 37, 47, 186, 171, 119, 164, 148, 126, 127, 163, 251, 195, 174, 204, 85, 164, 28, 54, 180, 88, 148, 88, 127, 35, 254, 124, 68, 53, 156, 171, 50, 178, 62, 8, 84, 4, 107, 249, 199, 97, 216, 214, 66, 181, 254, 240, 228, 65, 51, 243, 66, 240, 64, 117, 59, 178, 59, 96, 5, 191, 27, 140, 86, 240, 250, 55, 51, 169, 5, 53, 137, 245, 42, 186, 6, 39, 190, 127, 224, 179, 113, 102, 144, 154, 220, 108, 221, 186, 183, 163, 76, 96, 246, 96], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 5, 
					114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84]
			};

			let frag_1 = EncryptedBox { 
				nonce: vec![102, 209, 34, 179, 214, 75, 129, 24, 44, 14, 136, 104, 179, 34, 
					247, 161, 168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![231, 128, 154, 127, 160, 53, 16, 247, 143, 223, 24, 132, 166, 118, 11, 175, 101, 176, 255, 140, 209, 72, 126, 130, 164, 102, 59, 19, 60, 245, 81, 217, 122, 95, 138, 212, 60, 38, 18, 255, 98, 202, 221, 52, 217, 69, 19, 88, 129, 173, 123, 98, 119, 251, 147, 215, 60, 87, 253, 237, 21, 193, 20, 90, 230, 196, 94, 19, 42, 99, 252, 63, 184, 200, 148, 45, 67, 45, 33, 66, 201, 188, 222, 72, 49, 120, 72, 123, 202, 155, 130, 205, 169, 52, 62, 211, 32, 214, 130, 119, 162, 250, 185, 57, 108, 122, 227, 244, 50, 9, 223, 164, 112, 145, 58, 38, 7, 46, 15, 113, 84, 154, 84, 97, 129, 190, 237, 203, 94, 145, 210, 158, 149, 17, 235, 8, 94, 39, 36, 74, 112, 210, 96, 54, 12, 104, 17, 60, 123, 71, 18, 171, 126, 177, 200, 136, 73, 215, 113, 118, 142, 76, 243, 65, 236, 135, 192, 107, 115, 176, 56, 106, 126, 77, 245, 9, 23, 217, 52, 146, 224, 61, 95, 144, 225, 231, 70, 194, 156, 29, 208, 216, 198, 131, 246, 120, 30, 49, 126, 22, 197, 32, 250, 215, 168, 202, 131, 175, 217, 128, 110, 173, 254, 28, 14, 19, 236, 97, 31, 66, 236, 195, 172, 154, 40, 79, 75, 49, 111, 54, 13, 27, 191, 95, 132, 196, 34, 193, 105, 150, 35, 99, 106, 195, 226, 127, 10, 192, 107, 159, 195, 148, 91, 201, 168, 150, 5, 159, 9, 99, 27, 126, 171, 87, 201, 103, 170, 250, 38, 67, 212, 227, 180, 255, 246, 96], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 
					5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84] 
			};

			let consumer_pk = vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84];

			let call = mock::Call::IrisProxy(Call::submit_reencryption_keys { 
				consumer: consumer.clone().public(), 
				ephemeral_public_key: ephemeral_pk_vec.clone(), 
				data_public_key: vec![2, 32, 185, 106, 68, 174, 201, 135, 
					191, 34, 180, 13, 32, 162, 229, 
					68, 52, 118, 248, 52, 201, 84, 
					117, 230, 102, 195, 66, 63, 
					150, 109, 251, 201, 116], 
				kfrag_assignments: vec![
					(validators[0].clone().0, frag_0.clone()), 
					(validators[1].clone().0, frag_1.clone())
				],
				encrypted_sk_box: sk.clone(),
				consumer_public_key: consumer_pk.clone(),
				verifying_public_key: test_data.public_key.clone(),
			});

			// THEN: I can generate new key fragments for the caller
			assert_ok!(IrisProxy::proxy_process_kfrag_generation_requests(
				proxy.clone().public(),
				validators.clone(),
			));
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature.unwrap().0, 0);
			assert_eq!(call, tx.call);
			// Then: When the extrinsic is executed
			assert_ok!(IrisProxy::submit_reencryption_keys(
				Origin::signed(proxy.clone().public()),
				consumer.clone().public(),
				ephemeral_pk_vec.clone(),
				test_data.public_key.clone(),
				consumer_box_pk.as_bytes().to_vec().clone(),
				test_data.public_key.clone(),
				vec![(validators[0].clone().0, frag_0.clone()), 
					 (validators[1].clone().0, frag_1.clone())],
				sk.clone(),
			));
			// AND: I process reencryption requests
			assert_ok!(IrisProxy::kfrag_holder_process_reencryption_requests(
				validators[0].clone().0,
			));

			let encrypted_cfrag_0 = EncryptedBox { 
				nonce: vec![102, 209, 34, 179, 214, 75, 129, 24, 44, 14, 136, 104, 179, 34, 247, 161, 168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![77, 122, 28, 96, 15, 97, 134, 229, 114, 51, 52, 102, 228, 50, 131, 185, 10, 53, 35, 131, 213, 209, 137, 
					31, 125, 35, 38, 165, 138, 34, 97, 137, 21, 96, 230, 68, 81, 127, 241, 56, 177, 96, 104, 197, 191, 32, 236, 151, 81, 
					191, 29, 87, 107, 83, 191, 120, 178, 158, 26, 94, 240, 196, 245, 156, 218, 177, 160, 32, 136, 24, 157, 170, 28, 
					115, 230, 156, 3, 172, 218, 78, 111, 26, 176, 47, 49, 72, 52, 198, 230, 253, 159, 226, 197, 242, 4, 193, 193, 
					166, 134, 187, 180, 77, 181, 49, 181, 81, 120, 172, 88, 193, 39, 208, 124, 222, 49, 41, 254, 92, 102, 194, 27, 
					38, 213, 213, 15, 86, 157, 116, 151, 224, 106, 248, 98, 192, 4, 54, 222, 19, 152, 83, 133, 178, 202, 228, 214, 
					56, 5, 249, 139, 216, 94, 211, 23, 218, 179, 159, 31, 198, 201, 1, 153, 89, 60, 111, 159, 53, 196, 186, 142, 
					71, 241, 151, 236, 131, 92, 226, 203, 2, 76, 93, 235, 95, 233, 255, 218, 61, 147, 203, 124, 85, 31, 243, 160, 
					173, 140, 32, 71, 228, 71, 162, 163, 236, 63, 140, 38, 166, 176, 149, 151, 32, 27, 1, 61, 141, 149, 162, 147, 
					141, 162, 22, 45, 84, 45, 145, 10, 147, 202, 218, 241, 127, 138, 89, 254, 128, 186, 83, 82, 219, 252, 38, 170, 
					74, 22, 55, 162, 136, 29, 57, 178, 176, 79, 212, 119, 45, 107, 96, 32, 62, 48, 120, 116, 165, 81, 147, 27, 66,
					163, 243, 241, 4, 131, 125, 59, 79, 15, 190, 128, 154, 45, 211, 38, 25, 11, 104, 99, 178, 157, 40, 244, 91, 83, 
					252, 19, 39, 206, 67, 64, 43, 32, 47, 213, 43, 142, 141, 62, 112, 189, 54, 14, 195, 78, 37, 233, 72, 113, 28, 
					144, 95, 51, 147, 145, 236, 50, 189, 144, 125, 143, 254, 180, 138, 6, 70, 180, 206, 109, 191, 129, 143, 27, 57, 
					65, 3, 184, 8, 173, 87, 76, 243, 28, 200, 7, 200, 113, 254, 218, 193, 157, 133, 65, 208, 223, 61, 26, 43, 125, 
					137, 199, 152, 228, 85, 27, 62, 123, 38, 232], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43,
					 243, 37, 77, 126, 183, 5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84] 
			};

			let encrypted_cfrag_1 = EncryptedBox { 
				nonce: vec![102, 209, 34, 179, 214, 75, 129, 24, 44, 14, 136, 104, 179, 34, 247, 161, 168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![187, 97, 48, 87, 187, 103, 34, 175, 42, 13, 40, 72, 208, 144, 229, 29, 10, 163, 244, 187, 7, 123, 28, 48, 49, 73, 5, 69, 54, 19, 42, 64, 230, 68, 196, 103, 100, 115, 172, 229, 23, 234, 47, 21, 194, 237, 84, 122, 106, 191, 64, 173, 119, 119, 202, 29, 124, 110, 37, 171, 205, 64, 224, 65, 62, 104, 103, 11, 30, 184, 191, 19, 79, 216, 252, 189, 225, 200, 163, 38, 94, 84, 128, 121, 227, 226, 197, 13, 250, 80, 78, 67, 44, 116, 216, 50, 125, 204, 176, 149, 92, 98, 146, 136, 243, 200, 187, 66, 95, 151, 185, 37, 115, 27, 49, 41, 254, 92, 102, 194, 27, 38, 213, 213, 15, 86, 157, 116, 151, 224, 106, 248, 98, 192, 4, 54, 222, 19, 152, 83, 133, 178, 202, 228, 214, 56, 5, 249, 139, 216, 94, 211, 23, 218, 179, 159, 31, 198, 201, 1, 153, 89, 60, 111, 159, 53, 196, 186, 142, 71, 241, 151, 236, 131, 92, 226, 203, 2, 76, 93, 235, 95, 233, 255, 218, 61, 147, 203, 124, 85, 31, 243, 160, 173, 140, 32, 71, 228, 71, 162, 163, 236, 63, 140, 38, 166, 176, 149, 151, 32, 27, 1, 61, 141, 99, 154, 63, 93, 205, 194, 89, 10, 247, 64, 242, 124, 140, 170, 75, 128, 150, 63, 24, 177, 243, 23, 132, 159, 237, 48, 134, 254, 135, 192, 137, 85, 29, 57, 178, 176, 79, 212, 119, 45, 107, 96, 32, 62, 48, 120, 116, 165, 81, 147, 27, 66, 163, 243, 241, 4, 131, 125, 59, 79, 15, 190, 128, 154, 45, 65, 137, 102, 6, 13, 180, 230, 57, 177, 33, 228, 243, 220, 119, 79, 30, 175, 49, 248, 135, 162, 214, 221, 108, 156, 131, 3, 156, 235, 173, 17, 173, 215, 239, 132, 223, 44, 139, 231, 86, 231, 42, 199, 144, 201, 220, 23, 117, 75, 117, 1, 113, 120, 92, 51, 194, 123, 48, 150, 104, 107, 183, 37, 100, 121, 226, 227, 195, 3, 235, 144, 49, 14, 208, 44, 230, 67, 177, 134, 249, 103, 195, 198, 215, 241, 76, 208, 58, 238, 114, 174, 226, 93, 59, 222, 119], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43,
					 243, 37, 77, 126, 183, 5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84] 
			};

			let v_0_call = mock::Call::IrisProxy(Call::submit_capsule_fragment {
				data_consumer: consumer.public().clone(), 
				public_key: test_data.public_key.clone(), 
				encrypted_cfrag_data: encrypted_cfrag_0.clone()
			});

			let v_1_call = mock::Call::IrisProxy(Call::submit_capsule_fragment {
				data_consumer: consumer.public().clone(), 
				public_key: test_data.public_key.clone(), 
				encrypted_cfrag_data: encrypted_cfrag_1.clone()
			});

			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature.unwrap().0, 1);
			assert_eq!(v_0_call, tx.call);
			// And: I submit capsule fragments 
			assert_ok!(IrisProxy::submit_capsule_fragment(
				Origin::signed(validators[0].0.clone()),
				consumer.public().clone(),
				test_data.public_key.clone(),
				encrypted_cfrag_0.clone(),
			));

			assert_ok!(IrisProxy::kfrag_holder_process_reencryption_requests(
				validators[1].clone().0,
			));
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature.unwrap().0, 2);
			assert_eq!(v_1_call, tx.call);
			// And: I submit capsule fragments 
			assert_ok!(IrisProxy::submit_capsule_fragment(
				Origin::signed(validators[1].0.clone()),
				consumer.public().clone(),
				test_data.public_key.clone(),
				encrypted_cfrag_1.clone(),
			));

			let encrypted_sk = SecretKeys::<Test>::get(consumer.public().clone(), test_data.public_key.clone()).unwrap();
			let verifying_pk_bytes = VerifyingKeys::<Test>::get(consumer.public().clone(), test_data.public_key.clone());
			let new_verifying_pk = PublicKey::from_bytes(verifying_pk_bytes).unwrap();

			let capsule_data = Capsules::<Test>::get(test_data.public_key.clone()).unwrap();
			let capsule: Capsule = Capsule::from_bytes(capsule_data).unwrap();

			// When: I try to decrypt data
			let plaintext = IrisProxy::do_decrypt(
				consumer.public().clone(),
				ciphertext_bytes.to_vec().clone(),
				test_data.public_key.clone(),
				encrypted_sk.clone(),
				consumer_sk.clone(),
				new_verifying_pk.clone(),
				capsule,
			);
			// Then: the recovered plaintext matches the input plaintext
			assert_eq!(test_data.plaintext.clone(), plaintext.to_vec());
		});
	});
}

// #[test]
// fn can_decrypt() {
// 	TEST_CONSTANTS.with(|test_data| {
// 		// GIVEN: there are unique accounts for an owner, a proxy, and a consumer
// 		let owner = test_data.p.clone();
// 		let proxy = test_data.q.clone();
// 		let consumer = test_data.r.clone();

// 		let pairs = vec![(test_data.p.clone().public(), 10)];

// 		let mut rng = ChaCha20Rng::seed_from_u64(31u64);

// 		// AND: Offchain, the consumer generates a new secret key
// 		let consumer_sk = BoxSecretKey::generate(&mut rng);

// 		let validators = validators();
// 		let mut t = new_test_ext_funded(pairs, validators.clone());
// 		let (offchain, state) = testing::TestOffchainExt::new();
// 		let (pool, pool_state) = testing::TestTransactionPoolExt::new();

// 		let keystore = KeyStore::new();
// 		const PHRASE: &str =
// 			"news slush supreme milk chapter athlete soap sausage put clutch what kitten";
// 		SyncCryptoStore::sr25519_generate_new(
// 			&keystore,
// 			crate::crypto::Public::ID,
// 			Some(&format!("{}/hunter1", PHRASE)),
// 		).unwrap();

// 		t.register_extension(OffchainWorkerExt::new(offchain.clone()));
// 		t.register_extension(OffchainDbExt::new(offchain.clone()));
// 		t.register_extension(TransactionPoolExt::new(pool));
// 		t.register_extension(KeystoreExt(Arc::new(keystore)));

// 		t.execute_with(|| {

// 			// AND: the proxy node has created a new keypair
// 			assert_ok!(Authorities::create_secrets(
// 				Origin::signed(proxy.public().clone()),
// 			));
// 			let proxy_public_key = Authorities::x25519_public_keys(proxy.public().clone());
// 			let proxy_pk_32 = iris_primitives::slice_to_array_32(&proxy_public_key).unwrap();
// 			let proxy_pk = BoxPublicKey::from(*proxy_pk_32);

// 			let sk_box = EncryptedBox {
// 				nonce: vec![102, 209, 34, 179, 214, 75, 129,  24, 
// 							44, 14, 136, 104, 179, 34, 247, 161, 
// 							168, 16, 131, 113, 43, 29, 165, 49], 
// 				ciphertext: vec![76, 236, 32, 60, 161, 53, 11, 169, 11, 92, 15, 188, 173, 102, 6, 17, 88, 25, 228, 208, 149, 25, 5, 184, 97, 54, 40, 59, 237, 87, 50, 173, 62, 1, 200, 115, 87, 11, 160, 134, 139, 103, 194, 59, 123, 34, 227, 15], 
// 				public_key: vec![136, 127, 175, 150, 142, 160, 194, 
// 							185, 24, 43, 243, 37, 77, 126,  183, 
// 							5, 114, 157, 167, 133, 183, 81, 29, 
// 							217, 53, 237, 240, 233, 111, 29, 9, 84] 
// 			};

// 			let submit_encryption_artifacts_call = mock::Call::IrisProxy(Call::submit_encryption_artifacts { 
// 				owner: owner.clone().public(), 
// 				capsule: test_data.capsule.clone(), 
// 				public_key: test_data.public_key.clone(), 
// 				proxy: proxy.clone().public(), 
// 				sk_encryption_info: sk_box.clone(),
// 			});

// 			// GIVEN: Some data has been encrypted and added to the ingestion staging map
// 			let ciphertext = IrisProxy::do_encrypt(
// 				&test_data.plaintext.clone(),
// 				proxy_pk.clone(),
// 				owner.clone().public(),
// 				proxy.clone().public(),
// 			);
// 			let tx = pool_state.write().transactions.pop().unwrap();
// 			assert!(pool_state.read().transactions.is_empty());
// 			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
// 			assert_eq!(tx.signature, None);
// 			assert_eq!(submit_encryption_artifacts_call, tx.call);

// 			// now we want to simulate the extrinsic being executed
// 			assert_ok!(IrisProxy::submit_encryption_artifacts(
// 				Origin::signed(owner.clone().public()), 
// 				owner.clone().public(),  // owner
// 				test_data.capsule.clone(), // capsule
// 				test_data.public_key.clone(), // umbral pk
// 				proxy.clone().public(), // proxy
// 				sk_box.clone(), // encrypted sk to decrypt umbral sk 
// 			));
// 			// AND: I each validator has generated new keys using the authorities pallet
// 			assert_ok!(Authorities::create_secrets(
// 				Origin::signed(owner.public().clone()),
// 			));

// 			assert_ok!(Authorities::create_secrets(
// 				Origin::signed(consumer.public().clone()),
// 			));
// 			for v in validators.clone() {
// 				assert_ok!(Authorities::create_secrets(
// 					Origin::signed(v.0.clone())
// 				));
// 			}

// 			// THEN: The public key exists in the ingestion staging map
// 			// let new_public_key = DataAssets::ingestion_staging(test_data.p.clone().public()).unwrap();
// 			// WHEN: I simulate a new capsule recovery request for the data
// 			// Is this function completely insecure?
// 			IrisProxy::add_capsule_recovery_request(
// 				consumer.clone().public(),
// 				test_data.public_key.clone(),
// 				consumer_sk.public_key().clone().as_bytes().to_vec(),
// 			);


// 			let sk = EncryptedBox { 
// 				nonce: vec![102, 209, 34, 179, 214, 75, 129, 
// 					24, 44, 14, 136, 104, 179, 34, 247, 161, 
// 					168, 16, 131, 113, 43, 29, 165, 49], 
// 				ciphertext: vec![219, 140, 164, 182, 194, 125, 129, 157, 29, 37, 228, 22, 170, 32, 105, 162, 248, 245, 156, 187, 107, 237, 70, 78, 154, 125, 13, 223, 27, 213, 129, 103, 190, 3, 28, 75, 213, 140, 88, 7, 187, 101, 243, 146, 172, 11, 234, 31], 
// 				public_key: vec![136, 127, 175, 150, 142, 160, 
// 					194, 185, 24, 43, 243, 37, 77, 126, 183, 
// 					5, 114, 157, 167, 133, 183, 81, 29, 
// 					217, 53, 237, 240, 233, 111, 29, 9, 84] 
// 			};

// 			let ephemeral_pk_vec = vec![
// 				2, 74, 50, 75, 57, 138, 197, 
// 				248, 204, 201, 125, 87, 177, 81, 
// 				222, 20, 49, 128, 38, 251, 104, 
// 				211, 77, 79, 11, 140, 181, 7, 
// 				9, 76, 209, 226, 215
// 			];

// 			let frag_0 = EncryptedBox { 
// 				nonce: vec![102, 209, 34, 179, 214, 75, 
// 					129, 24, 44, 14, 136, 104, 179, 34, 247, 
// 					161, 168, 16, 131, 113, 43, 29, 165, 49], 
// 				ciphertext: vec![77, 44, 174, 139, 113, 253, 132, 254, 0, 152, 44, 45, 18, 40, 139, 120, 85, 230, 45, 38, 32, 131, 98, 47, 117, 199, 210, 149, 224, 6, 237, 179, 76, 113, 98, 251, 27, 159, 84, 102, 161, 36, 218, 98, 71, 176, 28, 157, 80, 206, 86, 9, 82, 190, 211, 66, 223, 148, 183, 45, 237, 119, 229, 165, 253, 133, 170, 185, 166, 87, 167, 156, 242, 189, 35, 61, 130, 59, 6, 53, 201, 188, 222, 72, 49, 120, 72, 123, 202, 155, 130, 205, 169, 52, 62, 211, 32, 214, 130, 119, 162, 250, 185, 57, 108, 122, 227, 244, 50, 9, 223, 164, 112, 145, 204, 30, 171, 254, 96, 165, 32, 196, 142, 176, 121, 81, 171, 187, 228, 110, 206, 248, 115, 32, 162, 76, 136, 99, 53, 92, 92, 102, 241, 193, 39, 181, 106, 68, 116, 146, 242, 239, 82, 245, 198, 176, 219, 104, 220, 7, 171, 85, 251, 170, 5, 255, 97, 73, 248, 138, 201, 69, 183, 217, 172, 108, 78, 20, 10, 72, 240, 113, 37, 47, 186, 171, 119, 164, 148, 126, 127, 163, 251, 195, 174, 204, 85, 164, 28, 54, 180, 88, 148, 88, 127, 35, 254, 124, 68, 53, 156, 171, 50, 178, 62, 8, 84, 4, 107, 249, 199, 97, 216, 214, 66, 181, 254, 240, 228, 65, 51, 243, 66, 240, 64, 117, 59, 178, 59, 96, 5, 191, 27, 140, 86, 240, 250, 55, 51, 169, 5, 53, 137, 245, 42, 186, 6, 39, 190, 127, 224, 179, 113, 102, 144, 154, 220, 108, 221, 186, 183, 163, 76, 96, 246, 96], 
// 				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 5, 
// 					114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84]
// 			};

// 			let frag_1 = EncryptedBox { 
// 				nonce: vec![102, 209, 34, 179, 214, 75, 129, 24, 44, 14, 136, 104, 179, 34, 
// 					247, 161, 168, 16, 131, 113, 43, 29, 165, 49], 
// 				ciphertext: vec![231, 128, 154, 127, 160, 53, 16, 247, 143, 223, 24, 132, 166, 118, 11, 175, 101, 176, 255, 140, 209, 72, 126, 130, 164, 102, 59, 19, 60, 245, 81, 217, 122, 95, 138, 212, 60, 38, 18, 255, 98, 202, 221, 52, 217, 69, 19, 88, 129, 173, 123, 98, 119, 251, 147, 215, 60, 87, 253, 237, 21, 193, 20, 90, 230, 196, 94, 19, 42, 99, 252, 63, 184, 200, 148, 45, 67, 45, 33, 66, 201, 188, 222, 72, 49, 120, 72, 123, 202, 155, 130, 205, 169, 52, 62, 211, 32, 214, 130, 119, 162, 250, 185, 57, 108, 122, 227, 244, 50, 9, 223, 164, 112, 145, 58, 38, 7, 46, 15, 113, 84, 154, 84, 97, 129, 190, 237, 203, 94, 145, 210, 158, 149, 17, 235, 8, 94, 39, 36, 74, 112, 210, 96, 54, 12, 104, 17, 60, 123, 71, 18, 171, 126, 177, 200, 136, 73, 215, 113, 118, 142, 76, 243, 65, 236, 135, 192, 107, 115, 176, 56, 106, 126, 77, 245, 9, 23, 217, 52, 146, 224, 61, 95, 144, 225, 231, 70, 194, 156, 29, 208, 216, 198, 131, 246, 120, 30, 49, 126, 22, 197, 32, 250, 215, 168, 202, 131, 175, 217, 128, 110, 173, 254, 28, 14, 19, 236, 97, 31, 66, 236, 195, 172, 154, 40, 79, 75, 49, 111, 54, 13, 27, 191, 95, 132, 196, 34, 193, 105, 150, 35, 99, 106, 195, 226, 127, 10, 192, 107, 159, 195, 148, 91, 201, 168, 150, 5, 159, 9, 99, 27, 126, 171, 87, 201, 103, 170, 250, 38, 67, 212, 227, 180, 255, 246, 96], 
// 				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 
// 					5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84] 
// 			};
// 			// TODO: MAKE THIS A TEST CONSTANT
// 			let verifying_pk = vec![2, 32, 185, 106, 68, 174, 
// 				201, 135, 191, 34, 180, 13, 32, 162, 229, 68, 52, 
// 				118, 248, 52, 201, 84, 117, 230, 102, 195, 
// 				66, 63, 150, 109, 251, 201, 116];

// 			let call = mock::Call::IrisProxy(Call::submit_reencryption_keys 
// 				{ 
// 					consumer: consumer.clone().public(), 
// 					ephemeral_public_key: ephemeral_pk_vec.clone(), 
// 					data_public_key: vec![2, 32, 185, 106, 68, 174, 201, 135, 
// 						191, 34, 180, 13, 32, 162, 229, 
// 						68, 52, 118, 248, 52, 201, 84, 
// 						117, 230, 102, 195, 66, 63, 
// 						150, 109, 251, 201, 116], 
// 					kfrag_assignments: vec![
// 						(validators[0].clone().0, frag_0.clone()), 
// 						(validators[1].clone().0, frag_1.clone())
// 					],
// 					encrypted_sk_box: sk.clone(),
// 					consumer_public_key: consumer_sk.public_key().clone().as_bytes().to_vec(),
// 					verifying_public_key: verifying_pk.clone(),
// 				}
// 			);

// 			// THEN: I can generate new key fragments for the caller
// 			assert_ok!(IrisProxy::proxy_process_kfrag_generation_requests(
// 				proxy.clone().public(),
// 				validators.clone().iter()
// 					.map(|v| (
// 						v.0,
// 						Authorities::x25519_public_keys(v.0.clone())
// 					)).collect::<Vec<_>>()
// 			));
// 			let tx = pool_state.write().transactions.pop().unwrap();
// 			assert!(pool_state.read().transactions.is_empty());
// 			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
// 			assert_eq!(tx.signature.unwrap().0, 0);
// 			assert_eq!(call, tx.call);
// 			// WHEN: the extrinsic is executed
			
// 			assert_ok!(IrisProxy::submit_reencryption_keys(
// 				Origin::signed(proxy.clone().public()),
// 				consumer.clone().public(),
// 				ephemeral_pk_vec.clone(),
// 				test_data.public_key.clone(),
// 				consumer_sk.public_key().clone().as_bytes().to_vec(),
// 				verifying_pk.clone(),
// 				vec![(validators[0].clone().0, frag_0.clone()), 
// 					 (validators[1].clone().0, frag_1.clone())],
// 				sk.clone(),
// 			));	
// 			// AND: I process reencryption requests for the first balidator
// 			assert_ok!(IrisProxy::kfrag_holder_process_reencryption_requests(
// 				validators[0].clone().0,
// 			));

// 			let encrypted_capsule_box = EncryptedBox { 
// 				nonce: vec![102, 209, 34, 179, 214, 75, 129, 24, 44, 14, 136, 104, 179, 
// 					34, 247, 161, 168, 16, 131, 113, 43, 29, 165, 49], 
// 				ciphertext: vec![77, 122, 28, 96, 15, 97, 134, 229, 114, 51, 52, 102, 228, 50, 131, 185, 10, 53, 35, 131, 213, 209, 137, 31, 125, 35, 38, 165, 138, 34, 97, 137, 21, 96, 230, 68, 81, 127, 241, 56, 177, 96, 104, 197, 191, 32, 236, 151, 81, 191, 29, 87, 107, 83, 191, 120, 178, 158, 26, 94, 240, 196, 245, 156, 218, 177, 160, 32, 136, 24, 157, 170, 28, 115, 230, 156, 3, 172, 218, 78, 111, 26, 176, 47, 49, 72, 52, 198, 230, 253, 159, 226, 197, 242, 4, 193, 193, 166, 134, 187, 180, 77, 181, 49, 181, 81, 120, 172, 88, 193, 39, 208, 124, 222, 49, 41, 254, 92, 102, 194, 27, 38, 213, 213, 15, 86, 157, 116, 151, 224, 106, 248, 98, 192, 4, 54, 222, 19, 152, 83, 133, 178, 202, 228, 214, 56, 5, 249, 139, 216, 94, 211, 23, 218, 179, 159, 31, 198, 201, 1, 153, 89, 60, 111, 159, 53, 196, 186, 142, 71, 241, 151, 236, 131, 92, 226, 203, 2, 76, 93, 235, 95, 233, 255, 218, 61, 147, 203, 124, 85, 31, 243, 160, 173, 140, 32, 71, 228, 71, 162, 163, 236, 63, 140, 38, 166, 176, 149, 151, 32, 27, 1, 61, 141, 149, 162, 147, 141, 162, 22, 45, 84, 45, 145, 10, 147, 202, 218, 241, 127, 138, 89, 254, 128, 186, 83, 82, 219, 252, 38, 170, 74, 22, 55, 162, 136, 29, 57, 178, 176, 79, 212, 119, 45, 107, 96, 32, 62, 48, 120, 116, 165, 81, 147, 27, 66, 163, 243, 241, 4, 131, 125, 59, 79, 15, 190, 128, 154, 45, 211, 38, 25, 11, 104, 99, 178, 157, 40, 244, 91, 83, 252, 19, 39, 206, 67, 64, 43, 32, 47, 213, 43, 142, 141, 62, 112, 189, 54, 14, 195, 78, 37, 233, 72, 113, 28, 144, 95, 51, 147, 145, 236, 50, 189, 144, 125, 143, 254, 180, 138, 6, 70, 180, 206, 109, 191, 129, 143, 27, 57, 65, 3, 184, 8, 173, 87, 76, 243, 28, 200, 7, 200, 113, 254, 218, 193, 157, 133, 65, 208, 223, 61, 26, 43, 125, 137, 199, 152, 228, 85, 27, 62, 123, 38, 232], 
// 				public_key: vec![136, 127, 175, 150, 142, 
// 					160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 5, 114, 157, 167, 133, 
// 					183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84] 
// 			};

// 			let submit_capsule_fragment_call = mock::Call::IrisProxy(Call::submit_capsule_fragment { 
// 				data_consumer: consumer.clone().public(), 
// 				public_key: vec![2, 32, 185, 106, 68, 174, 201, 135, 191, 34, 180, 13, 32, 162, 229, 68, 52, 
// 					118, 248, 52, 201, 84, 117, 230, 102, 195, 66, 63, 150, 109, 251, 201, 116], 
// 				encrypted_cfrag_data: encrypted_capsule_box.clone(),
// 			});

// 			let next_tx = pool_state.write().transactions.pop().unwrap();
// 			assert!(pool_state.read().transactions.is_empty());
// 			let next_tx = mock::Extrinsic::decode(&mut &*next_tx).unwrap();
// 			assert_eq!(next_tx.signature.unwrap().0, 1);
// 			// panic!("{:?}", next_tx.call);
// 			assert_eq!(submit_capsule_fragment_call, next_tx.call);
// 			// And: the extrinsic is executed successfully
// 			assert_ok!(IrisProxy::submit_capsule_fragment(
// 				Origin::signed(validators[0].0.clone()),
// 				consumer.clone().public(),
// 				test_data.public_key.clone(),
// 				encrypted_capsule_box.clone(),
// 			));

// 			// AND: I do the same for the second validator
// 			assert_ok!(IrisProxy::kfrag_holder_process_reencryption_requests(
// 				validators[1].clone().0,
// 			));

// 			let v1_encrypted_capsule_box = EncryptedBox { 
// 				nonce: vec![102, 209, 34, 179, 214, 75, 129, 24, 44, 14, 136, 104, 179, 
// 					34, 247, 161, 168, 16, 131, 113, 43, 29, 165, 49], 
// 				ciphertext: vec![187, 97, 48, 87, 187, 103, 34, 175, 42, 13, 40, 72, 208, 144, 229, 29, 10, 163, 244, 187, 7, 123, 28, 48, 49, 73, 5, 69, 54, 19, 42, 64, 230, 68, 196, 103, 100, 115, 172, 229, 23, 234, 47, 21, 194, 237, 84, 122, 106, 191, 64, 173, 119, 119, 202, 29, 124, 110, 37, 171, 205, 64, 224, 65, 62, 104, 103, 11, 30, 184, 191, 19, 79, 216, 252, 189, 225, 200, 163, 38, 94, 84, 128, 121, 227, 226, 197, 13, 250, 80, 78, 67, 44, 116, 216, 50, 125, 204, 176, 149, 92, 98, 146, 136, 243, 200, 187, 66, 95, 151, 185, 37, 115, 27, 49, 41, 254, 92, 102, 194, 27, 38, 213, 213, 15, 86, 157, 116, 151, 224, 106, 248, 98, 192, 4, 54, 222, 19, 152, 83, 133, 178, 202, 228, 214, 56, 5, 249, 139, 216, 94, 211, 23, 218, 179, 159, 31, 198, 201, 1, 153, 89, 60, 111, 159, 53, 196, 186, 142, 71, 241, 151, 236, 131, 92, 226, 203, 2, 76, 93, 235, 95, 233, 255, 218, 61, 147, 203, 124, 85, 31, 243, 160, 173, 140, 32, 71, 228, 71, 162, 163, 236, 63, 140, 38, 166, 176, 149, 151, 32, 27, 1, 61, 141, 99, 154, 63, 93, 205, 194, 89, 10, 247, 64, 242, 124, 140, 170, 75, 128, 150, 63, 24, 177, 243, 23, 132, 159, 237, 48, 134, 254, 135, 192, 137, 85, 29, 57, 178, 176, 79, 212, 119, 45, 107, 96, 32, 62, 48, 120, 116, 165, 81, 147, 27, 66, 163, 243, 241, 4, 131, 125, 59, 79, 15, 190, 128, 154, 45, 65, 137, 102, 6, 13, 180, 230, 57, 177, 33, 228, 243, 220, 119, 79, 30, 175, 49, 248, 135, 162, 214, 221, 108, 156, 131, 3, 156, 235, 173, 17, 173, 215, 239, 132, 223, 44, 139, 231, 86, 231, 42, 199, 144, 201, 220, 23, 117, 75, 117, 1, 113, 120, 92, 51, 194, 123, 48, 150, 104, 107, 183, 37, 100, 121, 226, 227, 195, 3, 235, 144, 49, 14, 208, 44, 230, 67, 177, 134, 249, 103, 195, 198, 215, 241, 76, 208, 58, 238, 114, 174, 226, 93, 59, 222, 119], 
// 				public_key: vec![136, 127, 175, 150, 142, 
// 					160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 5, 114, 157, 167, 133, 
// 					183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84] 
// 			};

// 			let v1_submit_capsule_fragment_call = mock::Call::IrisProxy(Call::submit_capsule_fragment { 
// 				data_consumer: consumer.clone().public(), 
// 				public_key: vec![2, 32, 185, 106, 68, 174, 201, 135, 191, 34, 180, 13, 32, 162, 229, 68, 52, 
// 					118, 248, 52, 201, 84, 117, 230, 102, 195, 66, 63, 150, 109, 251, 201, 116], 
// 				encrypted_cfrag_data: v1_encrypted_capsule_box.clone(),
// 			});

// 			let next_tx = pool_state.write().transactions.pop().unwrap();
// 			assert!(pool_state.read().transactions.is_empty());
// 			let next_tx = mock::Extrinsic::decode(&mut &*next_tx).unwrap();
// 			assert_eq!(next_tx.signature.unwrap().0, 2);
// 			// panic!("{:?}", next_tx.call);
// 			assert_eq!(v1_submit_capsule_fragment_call, next_tx.call);
// 			// And: the extrinsic is executed successfully
// 			assert_ok!(IrisProxy::submit_capsule_fragment(
// 				Origin::signed(validators[1].0.clone()),
// 				consumer.clone().public(),
// 				test_data.public_key.clone(),
// 				v1_encrypted_capsule_box.clone(),
// 			));


// 			let capsule_data = Capsules::<Test>::get(test_data.public_key.clone()).unwrap();
// 			let capsule: Capsule = Capsule::from_bytes(capsule_data).unwrap();

// 			let verifying_pk_bytes = VerifyingKeys::<Test>::get(consumer.public().clone(), verifying_pk.clone());
// 			let verifying_pk = PublicKey::from_bytes(verifying_pk_bytes).unwrap();

// 			// read secret key from SecretKeys
// 			let encrypted_consumer_decryption_key_bytes = SecretKeys::<Test>::get(
// 				consumer.public().clone(), test_data.public_key.clone(),
// 			).unwrap();
// 			// let consumer_decryption_key = 
// 			// When: I try to decrypt data
// 			let plaintext = IrisProxy::do_decrypt(
// 				consumer.public().clone(),
// 				ciphertext.to_vec().clone(),
// 				test_data.public_key.clone(),
// 				encrypted_consumer_decryption_key_bytes.clone(),
// 				consumer_sk.clone(),
// 				verifying_pk,
// 				capsule,
// 			);
// 			// Then: the recovered plaintext matches the input plaintext
// 			assert_eq!(test_data.plaintext.clone(), plaintext.to_vec());
// 		});
// 	});
// }


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
