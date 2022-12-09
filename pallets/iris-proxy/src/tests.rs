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
	assert_ok, pallet_prelude::*
};
use sp_runtime::{
	testing::UintAuthorityId,
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
use crypto_box::SecretKey;

struct TestData {
	pub owner: sp_core::sr25519::Pair,
	pub proxy: sp_core::sr25519::Pair,
	pub consumer: sp_core::sr25519::Pair,
	pub plaintext: Vec<u8>,
	pub ciphertext: Vec<u8>,
	pub public_key: Vec<u8>,
	pub capsule: Vec<u8>,
	pub nonce: Vec<u8>,
	pub x25519_pk: Vec<u8>,
}

thread_local!(static TEST_CONSTANTS: TestData = TestData {
	owner: sp_core::sr25519::Pair::generate().0,
	proxy: sp_core::sr25519::Pair::generate().0,
	consumer: sp_core::sr25519::Pair::generate().0,
	ciphertext: "ciphertext".as_bytes().to_vec(),
	plaintext: "plaintext".as_bytes().to_vec(),
	public_key: vec![2, 7, 178, 91, 140, 23, 162, 73, 101, 16, 100, 140, 126, 128, 189, 51, 190, 43, 204, 101, 196, 187, 116, 242, 164, 135, 50, 62, 121, 21, 39, 191, 68],
	capsule: vec![2, 7, 178, 91, 140, 23, 162, 73, 101, 16, 100, 140, 126, 128, 189, 51, 190, 43, 204, 101, 196, 187, 116, 242, 164, 135, 50, 62, 121, 21, 39, 191, 68, 3, 10, 130, 168, 14, 115, 158, 226, 143, 244, 181, 223, 210, 201, 139, 29, 65, 97, 32, 168, 140, 68, 186, 173, 72, 150, 112, 244, 66, 162, 46, 142, 226, 82, 104, 238, 89, 28, 1, 76, 159, 68, 159, 87, 201, 28, 254, 143, 212, 222, 42, 254, 44, 100, 100, 157, 252, 43, 91, 34, 219, 192, 199, 123, 25],
	nonce: vec![102, 209, 34, 179, 214, 75, 129,  24, 44, 14, 136, 104, 179, 34, 247, 161, 168, 16, 131, 113, 43, 29, 165, 49],
	x25519_pk: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126,  183, 5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84],
});

#[test]
fn can_submit_encryption_artifacts() {
	TEST_CONSTANTS.with(|test_data| { 
		// Given: I am a valid node with a positive balance
		let pairs = vec![(test_data.owner.clone().public(), 10)];
		let encrypted_key = EncryptedBox {
			nonce: test_data.nonce.clone(),
			ciphertext: test_data.ciphertext.clone(),
			public_key: test_data.public_key.clone(),
		};

		new_test_ext_funded(pairs, validators()).execute_with(|| {
			// When: I submit key fragments
			assert_ok!(IrisProxy::submit_encryption_artifacts(
				Origin::signed(test_data.owner.clone().public()),
				test_data.owner.clone().public(),
				test_data.proxy.clone().public(),
				test_data.capsule.clone(),
				test_data.public_key.clone(),
				encrypted_key.clone(),
			));
			
			let encryption_artifacts = EncryptionArtifacts::<Test>::get(test_data.public_key.clone()).unwrap();
			assert_eq!(encryption_artifacts.capsule, test_data.capsule.clone());
			assert_eq!(encryption_artifacts.proxy, test_data.proxy.clone().public());

			let proxy_code = ProxyCodes::<Test>::get(test_data.proxy.clone().public(), test_data.public_key.clone()).unwrap();
			assert_eq!(proxy_code, encrypted_key);
		}); 
	});
}

#[test]
fn can_submit_capsule_fragment() {
	TEST_CONSTANTS.with(|test_data| {
		let pairs = vec![(test_data.owner.clone().public(), 10)];
		let encrypted_capsule_fragment = iris_primitives::EncryptedBox {
			nonce: test_data.nonce.clone(),
			ciphertext: test_data.ciphertext.clone(),
			public_key: test_data.public_key.clone(),
		};

		new_test_ext_funded(pairs, validators()).execute_with(|| {
			assert_ok!(IrisProxy::submit_capsule_fragment(
				Origin::signed(test_data.proxy.clone().public()),
				test_data.consumer.clone().public(),
				test_data.public_key.clone(),
				encrypted_capsule_fragment.clone(),
			));

			let verified_cfrags = EncryptedCapsuleFrags::<Test>::get(
				test_data.consumer.clone().public(), test_data.public_key.clone()
			);
			assert_eq!(verified_cfrags.len(), 1);
			assert_eq!(verified_cfrags[0], encrypted_capsule_fragment.clone());
		});
	});
}

// #[test]
// fn submit_capsule_fragment_fails_if_public_key_unknown() {

// }

#[test]
fn can_submit_reencryption_keys() {
	TEST_CONSTANTS.with(|test_data| {
		let pairs = vec![(test_data.proxy.clone().public(), 10)];

		let encrypted_sk = EncryptedBox {
			ciphertext: test_data.ciphertext.clone(),
			nonce: test_data.nonce.clone(),
			public_key: test_data.public_key.clone(),
		};

		let kfrag_assignments = vec![(test_data.proxy.clone().public(), encrypted_sk.clone())];

		new_test_ext_funded(pairs, validators()).execute_with(|| {
			assert_ok!(IrisProxy::submit_reencryption_keys(
				Origin::signed(test_data.proxy.public().clone()),
				test_data.consumer.clone().public(),
				test_data.public_key.clone(),
				test_data.public_key.clone(),
				test_data.public_key.clone(),
				test_data.public_key.clone(),
				kfrag_assignments.clone(),
				encrypted_sk.clone(),
			));

			let reencryption_artifact = ReencryptionArtifacts::<Test>::get(
				test_data.consumer.clone().public(), test_data.public_key.clone(),
			).unwrap();
			assert_eq!(reencryption_artifact.verifying_key, test_data.public_key.clone());
			assert_eq!(reencryption_artifact.ephemeral_public_key, test_data.public_key.clone());
			assert_eq!(reencryption_artifact.secret, encrypted_sk);
			assert_eq!(reencryption_artifact.verified_kfrags, kfrag_assignments.clone());


		});
	});
}

/*
	offchain functionality
*/
#[test]
fn test_iris_protocol_happy_path() {
	TEST_CONSTANTS.with(|test_data| {
		let pairs = vec![
			(test_data.owner.clone().public(), 10),
			(test_data.consumer.clone().public(), 10),
			(test_data.proxy.clone().public(), 10)
		];

		let mut rng = ChaCha20Rng::seed_from_u64(31u64);

		// this is the new ephemeral keypair created by consumer 
		let consumer_sk = SecretKey::generate(&mut rng);
		let consumer_ephemeral_pk = consumer_sk.public_key();

		// let proxy_sk = SecretKey::generate(&mut rng);

		let validators = validators();
		let proxy = validators[0].clone();
		let mut t = new_test_ext_funded(pairs, validators.clone());
		let (offchain, _state) = testing::TestOffchainExt::new();
		let (pool, pool_state) = testing::TestTransactionPoolExt::new();

		let keystore = KeyStore::new();
		const PHRASE: &str =
			"news slush supreme milk chapter athlete soap sausage put clutch what kitten";
		SyncCryptoStore::sr25519_generate_new(
			&keystore,
			crate::crypto::Public::ID,
			Some(&format!("{}/tony1", PHRASE)),
		).unwrap();

		t.register_extension(OffchainWorkerExt::new(offchain.clone()));
		t.register_extension(OffchainDbExt::new(offchain.clone()));
		t.register_extension(TransactionPoolExt::new(pool));
		t.register_extension(KeystoreExt(Arc::new(keystore)));

		t.execute_with(|| {

			// generate new public key
			let mut rng = ChaCha20Rng::seed_from_u64(31u64);
			let secret_key = SecretKey::generate(&mut rng);
			let pk: Vec<u8> = secret_key.public_key().as_bytes().to_vec();

			Authorities::update_x25519();
			pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			
			assert_ok!(Authorities::insert_key(
				Origin::signed(test_data.owner.public().clone()), pk.clone(),
			));

		
			assert_ok!(Authorities::insert_key(
				Origin::signed(proxy.0.clone()), pk.clone(),
			));

			for v in validators.clone() {
				assert_ok!(Authorities::insert_key(
					Origin::signed(v.0.clone()), pk.clone(),
				));
			}	

			let sk_box = EncryptedBox {
				nonce: test_data.nonce.clone(),
				ciphertext: vec![155, 157, 182, 50, 148, 238, 223, 196, 62, 153, 134, 37, 58, 199, 71, 176, 83, 180, 73, 235, 143, 230, 221, 40, 9, 182, 4, 129, 230, 192, 13, 6, 47, 52, 14, 161, 121, 219, 204, 224, 237, 21, 139, 241, 15, 168, 189, 181], 
				public_key: test_data.x25519_pk.clone() ,
			};

			let submit_encryption_artifacts_call = mock::Call::IrisProxy(Call::submit_encryption_artifacts { 
				owner: test_data.owner.clone().public(),
				proxy: proxy.clone().0, 
				capsule: test_data.capsule.clone(), 
				public_key: test_data.public_key.clone(), 
				encrypted_sk_box: sk_box.clone(),
			});

			// GIVEN: Some data has been encrypted and added to the ingestion staging map
			let ciphertext_bytes = IrisProxy::do_encrypt(
				&test_data.plaintext.clone(),
				test_data.owner.clone().public(), // owner
				proxy.clone().0, // proxy
			);
			
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature, None);
			assert_eq!(submit_encryption_artifacts_call, tx.call);


			// now we want to simulate the extrinsic being executed
			assert_ok!(IrisProxy::submit_encryption_artifacts(
				Origin::signed(test_data.owner.clone().public()), 
				test_data.owner.clone().public(),  // owner
				proxy.clone().0, // proxy
				test_data.capsule.clone(), // capsule 
				test_data.public_key.clone(), // umbral pk
				sk_box.clone(), // encrypted sk to decrypt umbral sk 
			));

			// bypassing Authorization module
			IrisProxy::add_kfrag_request(
				test_data.consumer.clone().public(),
				test_data.public_key.clone(),
				consumer_ephemeral_pk.as_bytes().to_vec().clone(),
			);

			let ephemeral_pk_vec = vec![2, 63, 144, 248, 248, 201, 242, 155, 168, 30, 228, 157, 83, 19, 180, 139, 103, 158, 42, 198, 120, 113, 17, 126, 29, 187, 84, 22, 248, 203, 182, 239, 145];

			let frag_0 = EncryptedBox { 
				nonce: test_data.nonce.clone(), 
				public_key: test_data.x25519_pk.clone(),
				ciphertext: vec![247, 18, 198, 82, 236, 106, 20, 226, 111, 154, 109, 98, 90, 145, 233, 183, 250, 145, 197, 218, 77, 93, 23, 33, 41, 89, 56, 73, 233, 29, 31, 5, 72, 101, 73, 57, 174, 163, 157, 218, 185, 105, 169, 67, 48, 140, 51, 68, 247, 126, 112, 228, 20, 103, 209, 216, 242, 115, 247, 167, 201, 127, 2, 115, 121, 4, 131, 146, 8, 79, 235, 4, 115, 55, 154, 39, 54, 219, 224, 107, 201, 201, 124, 251, 240, 59, 127, 24, 174, 76, 27, 7, 75, 118, 84, 76, 118, 200, 142, 74, 178, 88, 229, 8, 122, 77, 2, 229, 195, 142, 184, 169, 54, 145, 87, 200, 179, 235, 44, 137, 74, 138, 56, 2, 199, 179, 132, 58, 51, 31, 151, 53, 253, 106, 52, 81, 184, 113, 240, 26, 173, 149, 199, 220, 170, 181, 88, 112, 44, 98, 254, 252, 155, 117, 128, 254, 162, 226, 130, 244, 90, 15, 167, 34, 232, 78, 53, 69, 117, 24, 10, 212, 56, 248, 197, 180, 234, 21, 2, 159, 219, 116, 253, 10, 68, 170, 54, 73, 225, 236, 175, 209, 170, 2, 245, 47, 228, 58, 176, 33, 243, 144, 178, 135, 18, 191, 186, 29, 75, 53, 133, 75, 189, 43, 10, 202, 34, 24, 41, 53, 208, 103, 56, 12, 67, 222, 3, 109, 196, 200, 148, 33, 66, 180, 43, 189, 151, 98, 222, 42, 47, 200, 52, 54, 27, 115, 151, 244, 153, 77, 139, 243, 21, 178, 68, 254, 61, 233, 155, 204, 149, 191, 87, 193, 119, 168, 244, 83, 227, 74, 84, 93, 115, 26, 246, 96], 
			};

			let frag_1 = EncryptedBox { 
				nonce: test_data.nonce.clone(), 
				public_key: test_data.x25519_pk.clone(),
				ciphertext: vec![161, 216, 252, 203, 193, 155, 29, 193, 13, 15, 118, 62, 186, 245, 143, 124, 250, 203, 30, 24, 34, 76, 33, 238, 39, 196, 246, 81, 71, 140, 222, 40, 161, 194, 194, 132, 115, 193, 239, 109, 75, 88, 145, 161, 147, 195, 14, 204, 12, 89, 253, 228, 167, 104, 220, 101, 66, 48, 123, 8, 107, 130, 8, 188, 119, 241, 174, 220, 217, 8, 182, 173, 17, 252, 242, 7, 144, 171, 199, 199, 201, 201, 124, 251, 240, 59, 127, 24, 174, 76, 27, 7, 75, 118, 84, 76, 118, 200, 142, 74, 178, 88, 229, 8, 122, 77, 2, 229, 195, 142, 184, 169, 54, 144, 144, 6, 171, 18, 22, 190, 11, 16, 230, 10, 164, 192, 4, 70, 221, 206, 71, 160, 176, 159, 26, 188, 74, 21, 139, 26, 81, 141, 171, 67, 164, 145, 80, 157, 24, 5, 170, 195, 41, 53, 19, 73, 239, 114, 54, 37, 40, 223, 183, 245, 29, 190, 71, 111, 52, 57, 254, 42, 189, 147, 127, 198, 173, 109, 108, 95, 76, 109, 221, 82, 181, 228, 82, 247, 221, 84, 221, 212, 19, 201, 111, 207, 40, 41, 61, 168, 92, 5, 95, 240, 255, 104, 225, 135, 110, 249, 95, 126, 122, 27, 90, 239, 217, 255, 80, 20, 81, 172, 114, 4, 151, 48, 190, 116, 86, 103, 20, 169, 217, 162, 108, 162, 101, 130, 63, 17, 80, 197, 24, 77, 105, 176, 66, 246, 26, 61, 159, 147, 99, 25, 174, 120, 39, 116, 144, 40, 11, 30, 190, 151, 19, 140, 214, 90, 237, 149, 80, 21, 118, 94, 246, 96], 
			};

			let frag_2 = EncryptedBox { 
				nonce: test_data.nonce.clone(), 
				public_key: test_data.x25519_pk.clone(),
				ciphertext: vec![24, 178, 131, 14, 248, 232, 28, 29, 14, 243, 139, 159, 99, 6, 53, 174, 195, 131, 241, 161, 124, 3, 107, 207, 167, 94, 29, 216, 88, 187, 223, 26, 148, 98, 1, 154, 77, 253, 181, 49, 232, 160, 212, 5, 79, 192, 169, 92, 233, 145, 170, 134, 102, 7, 238, 7, 115, 89, 132, 173, 232, 29, 67, 133, 98, 182, 151, 166, 154, 174, 173, 83, 114, 232, 252, 100, 80, 73, 191, 120, 201, 201, 124, 251, 240, 59, 127, 24, 174, 76, 27, 7, 75, 118, 84, 76, 118, 200, 142, 74, 178, 88, 229, 8, 122, 77, 2, 229, 195, 142, 184, 169, 54, 144, 151, 91, 134, 166, 48, 215, 226, 20, 54, 118, 226, 245, 109, 96, 82, 180, 150, 19, 253, 199, 24, 220, 59, 160, 70, 162, 181, 153, 186, 165, 107, 147, 149, 112, 47, 114, 162, 91, 229, 18, 131, 219, 125, 82, 189, 103, 249, 242, 50, 171, 171, 37, 86, 192, 168, 141, 82, 226, 16, 56, 101, 172, 161, 81, 94, 120, 195, 23, 241, 180, 64, 215, 160, 148, 200, 35, 111, 0, 157, 83, 222, 61, 41, 216, 142, 229, 178, 234, 131, 61, 52, 147, 214, 223, 83, 212, 4, 212, 45, 97, 55, 72, 241, 205, 44, 230, 127, 50, 252, 154, 113, 151, 138, 17, 139, 227, 241, 87, 174, 145, 56, 144, 195, 72, 36, 227, 212, 217, 72, 174, 42, 16, 27, 73, 62, 30, 76, 227, 246, 181, 153, 206, 209, 188, 150, 146, 72, 30, 118, 141, 20, 36, 16, 137, 134, 75, 69, 84, 152, 207, 246, 96], 
			};
			let consumer_pk = vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84];

			let encrypted_receiving_sk = EncryptedBox {
				nonce: test_data.nonce.clone(), 
				public_key: test_data.x25519_pk.clone(),
				ciphertext: vec![103, 77, 91, 193, 13, 150, 184, 196, 151, 197, 24, 130, 29, 254, 134, 97, 33, 235, 189, 114, 226, 177, 224, 84, 255, 131, 160, 36, 156, 222, 195, 90, 68, 90, 162, 11, 66, 238, 90, 83, 232, 118, 116, 104, 115, 97, 161, 104],
			};

			let call = mock::Call::IrisProxy(Call::submit_reencryption_keys { 
				consumer: test_data.consumer.clone().public(), 
				receiving_public_key: ephemeral_pk_vec.clone(), 
				delegating_public_key: test_data.public_key.clone(), 
				kfrag_assignments: vec![
					(validators[0].clone().0, frag_0.clone()), 
					(validators[1].clone().0, frag_1.clone()),
					(validators[2].clone().0, frag_2.clone()),
				],
				encrypted_receiving_sk: encrypted_receiving_sk.clone(),
				consumer_public_key: consumer_pk.clone(),
				verifying_public_key: test_data.public_key.clone(),
			});

			let candidates = validators.clone().iter().map(|v| v.0).collect::<Vec<_>>();
			// THEN: I can generate new key fragments for the caller
			assert_ok!(IrisProxy::proxy_process_kfrag_generation_requests(
				proxy.clone().0,
				candidates.clone(),
			));
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature.unwrap().0, 1);
			assert_eq!(call, tx.call);
			// // // Then: When the extrinsic is executed
			assert_ok!(IrisProxy::submit_reencryption_keys(
				Origin::signed(proxy.clone().0),
				test_data.consumer.clone().public(),
				ephemeral_pk_vec.clone(),
				test_data.public_key.clone(),
				consumer_ephemeral_pk.as_bytes().to_vec().clone(),
				test_data.public_key.clone(),
				vec![
					(validators[0].clone().0, frag_0.clone()), 
					(validators[1].clone().0, frag_1.clone()),
					(validators[2].clone().0, frag_2.clone()),
				],
				encrypted_receiving_sk.clone(),
			));
			// AND: I process reencryption requests
			assert_ok!(IrisProxy::kfrag_holder_process_reencryption_requests(
				validators[0].clone().0,
			));

			let encrypted_cfrag_0 = EncryptedBox { 
				nonce: test_data.nonce.clone(), 
				public_key: test_data.x25519_pk.clone(),
				ciphertext: vec![205, 30, 94, 241, 154, 185, 205, 232, 31, 134, 110, 188, 95, 157, 125, 44, 10, 53, 108, 82, 95, 227, 60, 59, 72, 135, 194, 21, 216, 98, 202, 179, 236, 225, 199, 78, 187, 202, 30, 5, 57, 100, 41, 160, 25, 17, 146, 228, 17, 190, 136, 103, 146, 188, 158, 252, 142, 231, 127, 148, 223, 226, 177, 9, 69, 100, 56, 103, 131, 206, 82, 33, 54, 250, 69, 147, 203, 140, 222, 32, 179, 206, 31, 88, 217, 180, 89, 24, 147, 243, 195, 124, 47, 46, 13, 218, 51, 16, 130, 175, 159, 143, 0, 13, 124, 237, 96, 225, 43, 224, 80, 236, 83, 7, 49, 92, 92, 239, 167, 129, 44, 69, 177, 2, 150, 156, 127, 54, 253, 127, 60, 230, 110, 253, 20, 148, 130, 34, 142, 100, 100, 163, 59, 99, 177, 53, 67, 248, 222, 67, 255, 236, 159, 109, 238, 110, 96, 214, 53, 159, 24, 16, 44, 18, 203, 157, 86, 217, 131, 164, 57, 104, 26, 152, 66, 38, 249, 213, 158, 197, 235, 209, 179, 221, 120, 68, 246, 13, 3, 155, 201, 235, 188, 154, 232, 221, 52, 212, 23, 75, 238, 125, 102, 26, 85, 218, 200, 175, 84, 212, 46, 150, 105, 141, 14, 116, 139, 152, 238, 58, 71, 26, 155, 35, 180, 113, 229, 91, 38, 14, 211, 148, 112, 202, 44, 78, 98, 201, 57, 96, 91, 185, 32, 42, 47, 136, 28, 80, 39, 140, 138, 183, 170, 196, 221, 172, 29, 165, 104, 229, 33, 201, 8, 34, 232, 60, 113, 151, 20, 68, 34, 158, 56, 164, 245, 21, 3, 251, 30, 10, 120, 52, 128, 160, 51, 92, 215, 125, 68, 22, 146, 238, 105, 168, 27, 243, 32, 67, 202, 192, 28, 195, 179, 87, 62, 104, 253, 147, 30, 195, 232, 60, 9, 199, 232, 40, 82, 41, 47, 209, 93, 251, 52, 93, 74, 124, 228, 3, 41, 170, 143, 225, 102, 206, 41, 212, 73, 35, 203, 220, 11, 41, 207, 39, 23, 26, 207, 158, 223, 98, 227, 70, 183, 98, 157, 175, 217, 190, 143, 245, 108, 72, 22, 13, 218, 110, 245, 176, 219, 107, 235, 221, 133, 25, 146], 
			};

			let v_0_call = mock::Call::IrisProxy(Call::submit_capsule_fragment {
				data_consumer: test_data.consumer.public().clone(), 
				public_key: test_data.public_key.clone(), 
				encrypted_cfrag_data: encrypted_cfrag_0.clone()
			});

			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature.unwrap().0, 2);
			assert_eq!(v_0_call, tx.call);
			// // And: I submit capsule fragments 
			assert_ok!(IrisProxy::submit_capsule_fragment(
				Origin::signed(validators[0].0.clone()),
				test_data.consumer.public().clone(),
				test_data.public_key.clone(),
				encrypted_cfrag_0.clone(),
			));

			let encrypted_cfrag_1 = EncryptedBox { 
				nonce: test_data.nonce.clone(), 
				public_key: test_data.x25519_pk.clone(),
				ciphertext: vec![255, 31, 73, 99, 158, 132, 255, 175, 231, 180, 90, 179, 21, 128, 106, 185, 11, 251, 169, 105, 105, 223, 90, 229, 102, 5, 220, 2, 98, 26, 242, 253, 123, 172, 22, 98, 55, 86, 134, 97, 195, 130, 196, 114, 197, 192, 215, 31, 148, 190, 228, 66, 253, 170, 101, 248, 235, 224, 29, 93, 75, 163, 109, 234, 103, 176, 109, 205, 132, 12, 118, 172, 150, 156, 35, 15, 57, 151, 202, 233, 149, 131, 31, 2, 2, 118, 54, 9, 165, 60, 205, 225, 225, 54, 163, 75, 242, 61, 107, 8, 20, 50, 221, 111, 14, 90, 146, 208, 19, 2, 243, 163, 110, 143, 49, 92, 92, 239, 167, 129, 44, 69, 177, 2, 150, 156, 127, 54, 253, 127, 60, 230, 110, 253, 20, 148, 130, 34, 142, 100, 100, 163, 59, 99, 177, 53, 67, 248, 222, 67, 255, 236, 159, 109, 238, 110, 96, 214, 53, 159, 24, 16, 44, 18, 203, 157, 86, 217, 131, 164, 57, 104, 26, 152, 66, 38, 249, 213, 158, 197, 235, 209, 179, 221, 120, 68, 246, 13, 3, 155, 201, 235, 188, 154, 232, 221, 52, 212, 23, 75, 238, 125, 102, 26, 85, 218, 200, 175, 84, 212, 46, 150, 105, 140, 201, 186, 147, 97, 212, 13, 6, 128, 69, 43, 215, 2, 101, 39, 200, 223, 3, 1, 61, 63, 2, 163, 144, 173, 66, 96, 167, 161, 76, 181, 33, 172, 28, 80, 39, 140, 138, 183, 170, 196, 221, 172, 29, 165, 104, 229, 33, 201, 8, 34, 232, 60, 113, 151, 20, 68, 34, 158, 56, 164, 245, 21, 3, 251, 30, 128, 91, 103, 217, 76, 30, 149, 168, 129, 59, 198, 79, 56, 108, 152, 227, 52, 153, 209, 110, 84, 192, 140, 255, 218, 82, 40, 77, 175, 128, 156, 170, 230, 60, 0, 216, 120, 119, 210, 200, 168, 124, 122, 255, 23, 66, 168, 10, 190, 48, 56, 32, 97, 238, 85, 63, 147, 86, 209, 43, 61, 48, 86, 194, 11, 108, 104, 12, 75, 221, 225, 147, 82, 215, 20, 54, 69, 95, 164, 18, 254, 136, 214, 183, 228, 140, 10, 209, 146, 210, 101, 52, 217, 205, 28, 214], 
			};

			let v_1_call = mock::Call::IrisProxy(Call::submit_capsule_fragment {
				data_consumer: test_data.consumer.public().clone(), 
				public_key: test_data.public_key.clone(), 
				encrypted_cfrag_data: encrypted_cfrag_1.clone()
			});

			assert_ok!(IrisProxy::kfrag_holder_process_reencryption_requests(
				validators[1].clone().0,
			));
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature.unwrap().0, 3);
			assert_eq!(v_1_call, tx.call);
			// And: I submit capsule fragments 
			assert_ok!(IrisProxy::submit_capsule_fragment(
				Origin::signed(validators[1].0.clone()),
				test_data.consumer.public().clone(),
				test_data.public_key.clone(),
				encrypted_cfrag_1.clone(),
			));


			let encrypted_cfrag_2 = EncryptedBox { 
				nonce: test_data.nonce.clone(), 
				public_key: test_data.x25519_pk.clone(),
				ciphertext: vec![31, 252, 9, 61, 32, 38, 32, 113, 130, 128, 11, 189, 252, 226, 34, 185, 10, 94, 114, 186, 49, 45, 18, 94, 54, 186, 86, 241, 171, 40, 6, 221, 19, 212, 243, 96, 175, 200, 215, 141, 126, 16, 160, 76, 51, 49, 251, 214, 24, 191, 204, 98, 190, 250, 164, 74, 220, 63, 220, 241, 24, 105, 198, 153, 226, 11, 221, 252, 178, 112, 116, 53, 172, 87, 243, 217, 28, 246, 17, 214, 90, 208, 38, 74, 237, 207, 104, 70, 239, 29, 77, 123, 10, 191, 188, 124, 243, 15, 94, 168, 215, 44, 227, 83, 84, 6, 49, 40, 86, 166, 47, 160, 201, 31, 49, 92, 92, 239, 167, 129, 44, 69, 177, 2, 150, 156, 127, 54, 253, 127, 60, 230, 110, 253, 20, 148, 130, 34, 142, 100, 100, 163, 59, 99, 177, 53, 67, 248, 222, 67, 255, 236, 159, 109, 238, 110, 96, 214, 53, 159, 24, 16, 44, 18, 203, 157, 86, 217, 131, 164, 57, 104, 26, 152, 66, 38, 249, 213, 158, 197, 235, 209, 179, 221, 120, 68, 246, 13, 3, 155, 201, 235, 188, 154, 232, 221, 52, 212, 23, 75, 238, 125, 102, 26, 85, 218, 200, 175, 84, 212, 46, 150, 105, 140, 206, 231, 190, 213, 242, 100, 239, 132, 149, 87, 145, 55, 12, 1, 71, 165, 210, 178, 112, 103, 0, 195, 225, 24, 143, 216, 67, 181, 93, 83, 238, 174, 28, 80, 39, 140, 138, 183, 170, 196, 221, 172, 29, 165, 104, 229, 33, 201, 8, 34, 232, 60, 113, 151, 20, 68, 34, 158, 56, 164, 245, 21, 3, 251, 30, 80, 63, 30, 232, 209, 133, 177, 36, 29, 6, 114, 201, 187, 231, 52, 129, 77, 71, 192, 118, 92, 146, 225, 235, 231, 65, 143, 110, 163, 15, 59, 89, 189, 150, 87, 162, 21, 208, 250, 250, 212, 142, 84, 97, 153, 220, 78, 173, 138, 85, 229, 164, 132, 16, 34, 12, 199, 100, 119, 225, 38, 194, 210, 222, 91, 143, 43, 172, 18, 98, 197, 176, 129, 167, 129, 154, 114, 233, 82, 218, 248, 50, 149, 183, 44, 150, 13, 121, 84, 1, 14, 234, 204, 140, 242, 71], 
			};
			let v_2_call = mock::Call::IrisProxy(Call::submit_capsule_fragment {
				data_consumer: test_data.consumer.public().clone(), 
				public_key: test_data.public_key.clone(), 
				encrypted_cfrag_data: encrypted_cfrag_2.clone()
			});

			assert_ok!(IrisProxy::kfrag_holder_process_reencryption_requests(
				validators[2].clone().0,
			));
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature.unwrap().0, 4);
			assert_eq!(v_2_call, tx.call);
			// And: I submit capsule fragments 
			assert_ok!(IrisProxy::submit_capsule_fragment(
				Origin::signed(validators[2].0.clone()),
				test_data.consumer.public().clone(),
				test_data.public_key.clone(),
				encrypted_cfrag_2.clone(),
			));

			// When: I try to decrypt data
			let plaintext = IrisProxy::do_decrypt(
				test_data.consumer.public().clone(),
				ciphertext_bytes.to_vec().clone(),
				test_data.public_key.clone(),
				consumer_sk.clone(),
			);
			// Then: the recovered plaintext matches the input plaintext
			assert_eq!(test_data.plaintext.clone(), plaintext.to_vec());
		});
	});
}

// #[test]
// fn add_capsule_recovery_request_fails_if_no_proxy_for_public_key() {

// }

// #[test]
// pub fn rpc_encrypt_can_encrypt_and_submit_signed_tx() {
// }

// #[test]
// pub fn rpc_encrypt_fails_if_shares_exceeds_validator_count() {
	
// }

// #[test]
// pub fn rpc_decrypt_fail_if_no_cfrags() {

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
