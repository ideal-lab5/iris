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
	pub owner: sp_core::sr25519::Pair,
	pub proxy: sp_core::sr25519::Pair,
	pub consumer: sp_core::sr25519::Pair,
	pub plaintext: Vec<u8>,
	pub ciphertext: Vec<u8>,
	pub public_key: Vec<u8>,
	pub capsule: Vec<u8>,
	pub nonce: Vec<u8>,
}

thread_local!(static TEST_CONSTANTS: TestData = TestData {
	owner: sp_core::sr25519::Pair::generate().0,
	proxy: sp_core::sr25519::Pair::generate().0,
	consumer: sp_core::sr25519::Pair::generate().0,
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
		let consumer_sk = BoxSecretKey::generate(&mut rng);
		let consumer_ephemeral_pk = consumer_sk.public_key();

		let proxy_sk = BoxSecretKey::generate(&mut rng);

		let validators = validators();
		let proxy = validators[0].clone();
		let mut t = new_test_ext_funded(pairs, validators.clone());
		let (offchain, state) = testing::TestOffchainExt::new();
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
			let secret_key = BoxSecretKey::generate(&mut rng);
			let pk: Vec<u8> = secret_key.public_key().as_bytes().to_vec();

			// TODO: remoiving create_secret as extrinsic, need to call as function instead
			// Given: validator and proxies have generated secrets
			Authorities::update_x25519(test_data.owner.public().clone());
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			assert_ok!(Authorities::insert_key(
				Origin::signed(test_data.owner.public().clone()), pk.clone(),
			));

			Authorities::update_x25519(proxy.0.clone());
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			assert_ok!(Authorities::insert_key(
				Origin::signed(proxy.0.clone()), pk.clone(),
			));

			for v in validators.clone() {
				Authorities::update_x25519(v.0.clone());
				let tx = pool_state.write().transactions.pop().unwrap();
				assert!(pool_state.read().transactions.is_empty());
				assert_ok!(Authorities::insert_key(
					Origin::signed(v.0.clone()), pk.clone(),
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
				ciphertext: vec![144, 116, 211, 152, 192, 87, 121, 202, 176, 72, 23, 122, 212, 116, 180, 179, 37, 84, 123, 188, 219, 164, 247, 49, 141, 199, 86, 48, 148, 146, 166, 136, 139, 97, 44, 80, 2, 21, 215, 18, 207, 245, 107, 46, 245, 246, 79, 33, 143, 201, 233, 234, 102, 92, 67, 60, 177, 214, 232, 13, 35, 53, 90, 134, 74, 147, 192, 94, 0, 107, 225, 93, 122, 88, 2, 135, 195, 23, 95, 234, 201, 188, 222, 72, 49, 120, 72, 123, 202, 155, 130, 205, 169, 52, 62, 211, 32, 214, 130, 119, 162, 250, 185, 57, 108, 122, 227, 244, 50, 9, 223, 164, 112, 144, 110, 210, 245, 142, 148, 229, 151, 61, 194, 141, 117, 91, 82, 248, 30, 179, 235, 89, 64, 27, 106, 157, 242, 79, 187, 159, 57, 40, 44, 91, 55, 95, 155, 109, 48, 95, 140, 127, 62, 88, 229, 168, 7, 192, 185, 74, 160, 65, 118, 139, 160, 94, 170, 135, 187, 84, 167, 73, 65, 137, 74, 104, 85, 97, 33, 20, 135, 232, 251, 8, 93, 21, 192, 22, 242, 44, 133, 192, 152, 76, 73, 74, 2, 138, 101, 0, 2, 132, 200, 202, 60, 130, 37, 185, 243, 102, 81, 222, 101, 199, 178, 102, 57, 17, 43, 169, 137, 87, 214, 24, 57, 126, 191, 235, 163, 119, 96, 234, 236, 148, 207, 55, 17, 132, 228, 49, 52, 97, 123, 128, 137, 170, 240, 115, 68, 63, 253, 215, 251, 7, 92, 54, 20, 83, 32, 152, 174, 160, 194, 115, 202, 17, 237, 94, 194, 239, 67, 184, 137, 93, 246, 96], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 5, 
					114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84]
			};

			let frag_1 = EncryptedBox { 
				nonce: vec![102, 209, 34, 179, 214, 75, 129, 24, 44, 14, 136, 104, 179, 34, 
					247, 161, 168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![151, 142, 57, 191, 224, 227, 82, 109, 215, 99, 157, 181, 231, 99, 58, 255, 110, 64, 182, 195, 221, 102, 137, 247, 7, 175, 162, 0, 223, 168, 131, 213, 195, 121, 66, 84, 139, 128, 185, 184, 183, 166, 123, 51, 176, 117, 41, 216, 79, 205, 68, 66, 161, 247, 121, 1, 191, 39, 113, 168, 215, 245, 197, 89, 244, 64, 133, 207, 2, 190, 195, 179, 243, 245, 252, 135, 236, 53, 45, 183, 201, 188, 222, 72, 49, 120, 72, 123, 202, 155, 130, 205, 169, 52, 62, 211, 32, 214, 130, 119, 162, 250, 185, 57, 108, 122, 227, 244, 50, 9, 223, 164, 112, 145, 7, 202, 97, 174, 96, 42, 102, 230, 116, 68, 90, 225, 205, 129, 234, 117, 87, 120, 188, 180, 189, 168, 17, 32, 149, 1, 150, 13, 10, 116, 55, 161, 110, 213, 85, 212, 208, 234, 113, 76, 124, 201, 112, 74, 145, 42, 164, 20, 241, 217, 135, 14, 4, 202, 31, 168, 180, 181, 140, 73, 66, 33, 89, 184, 50, 184, 163, 216, 53, 185, 38, 67, 176, 229, 40, 32, 177, 154, 188, 93, 106, 23, 115, 182, 206, 240, 249, 122, 63, 16, 110, 245, 89, 231, 95, 181, 230, 186, 216, 191, 232, 172, 153, 239, 60, 220, 35, 168, 159, 201, 19, 71, 73, 175, 195, 181, 144, 212, 222, 4, 251, 194, 229, 84, 246, 47, 82, 226, 97, 23, 142, 143, 21, 20, 103, 131, 101, 161, 202, 231, 4, 20, 64, 44, 75, 16, 90, 210, 158, 49, 187, 155, 65, 115, 71, 41, 67, 166, 229, 71, 246, 96], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 
					5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84] 
			};

			let frag_2 = EncryptedBox { 
				nonce: vec![102, 209, 34, 179, 214, 75, 129, 24, 44, 14, 136, 104, 179, 34, 
					247, 161, 168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![202, 137, 250, 28, 22, 125, 109, 234, 61, 239, 94, 82, 196, 233, 93, 235, 221, 130, 69, 16, 13, 169, 131, 66, 68, 213, 207, 80, 185, 12, 12, 204, 251, 146, 148, 90, 226, 127, 89, 74, 1, 252, 102, 77, 174, 11, 68, 247, 117, 208, 180, 201, 133, 71, 75, 181, 114, 13, 183, 177, 199, 200, 179, 142, 207, 220, 45, 22, 128, 239, 187, 34, 96, 208, 227, 100, 203, 163, 151, 8, 201, 188, 222, 72, 49, 120, 72, 123, 202, 155, 130, 205, 169, 52, 62, 211, 32, 214, 130, 119, 162, 250, 185, 57, 108, 122, 227, 244, 50, 9, 223, 164, 112, 145, 211, 234, 149, 17, 7, 201, 10, 247, 214, 172, 211, 25, 18, 61, 25, 153, 144, 134, 171, 211, 8, 229, 37, 144, 114, 254, 244, 34, 166, 49, 168, 219, 18, 223, 125, 136, 28, 91, 95, 230, 92, 159, 192, 146, 89, 113, 52, 237, 86, 95, 125, 202, 74, 208, 162, 240, 122, 2, 102, 228, 244, 128, 22, 235, 75, 137, 231, 28, 137, 48, 108, 214, 93, 59, 159, 64, 195, 60, 40, 131, 29, 249, 45, 86, 58, 107, 75, 47, 172, 98, 97, 235, 126, 121, 26, 26, 125, 133, 216, 77, 61, 173, 221, 161, 97, 82, 71, 166, 2, 84, 155, 151, 162, 169, 221, 93, 38, 18, 213, 205, 142, 169, 154, 164, 94, 145, 129, 89, 75, 58, 207, 200, 252, 93, 193, 245, 129, 85, 210, 180, 197, 102, 4, 10, 149, 58, 201, 229, 251, 239, 19, 242, 222, 171, 133, 8, 189, 231, 244, 152, 246, 96], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 
					5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84] 
			};
			let consumer_pk = vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84];

			let call = mock::Call::IrisProxy(Call::submit_reencryption_keys { 
				consumer: test_data.consumer.clone().public(), 
				receiving_public_key: ephemeral_pk_vec.clone(), 
				delegating_public_key: test_data.public_key.clone(), 
				kfrag_assignments: vec![
					(validators[0].clone().0, frag_0.clone()), 
					(validators[1].clone().0, frag_1.clone()),
					(validators[2].clone().0, frag_2.clone()),
				],
				encrypted_receiving_sk: sk.clone(),
				consumer_public_key: consumer_pk.clone(),
				verifying_public_key: test_data.public_key.clone(),
			});

			let candidates = validators.clone().iter().map(|v| v.0).collect::<Vec<_>>();
			// // THEN: I can generate new key fragments for the caller
			assert_ok!(IrisProxy::proxy_process_kfrag_generation_requests(
				proxy.clone().0,
				candidates.clone(),
			));
			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature.unwrap().0, 5);
			assert_eq!(call, tx.call);
			// // Then: When the extrinsic is executed
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
				sk.clone(),
			));
			// AND: I process reencryption requests
			assert_ok!(IrisProxy::kfrag_holder_process_reencryption_requests(
				validators[0].clone().0,
			));

			let encrypted_cfrag_0 = EncryptedBox { 
				nonce: vec![102, 209, 34, 179, 214, 75, 129, 24, 44, 14, 136, 104, 179, 34, 247, 161, 168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![181, 62, 214, 171, 193, 108, 105, 186, 99, 182, 152, 186, 226, 110, 132, 56, 11, 11, 173, 171, 131, 185, 220, 2, 49, 23, 156, 145, 101, 218, 3, 186, 9, 144, 194, 243, 204, 37, 237, 28, 227, 210, 149, 10, 4, 146, 204, 254, 71, 190, 183, 7, 1, 159, 89, 90, 6, 111, 1, 83, 39, 25, 182, 213, 139, 25, 61, 230, 138, 83, 25, 121, 218, 165, 253, 192, 0, 197, 9, 33, 74, 230, 192, 157, 103, 210, 207, 225, 115, 227, 103, 226, 65, 87, 112, 85, 138, 157, 65, 171, 250, 230, 172, 187, 54, 37, 22, 125, 233, 141, 149, 150, 47, 98, 49, 41, 254, 92, 102, 194, 27, 38, 213, 213, 15, 86, 157, 116, 151, 224, 106, 248, 98, 192, 4, 54, 222, 19, 152, 83, 133, 178, 202, 228, 214, 56, 5, 249, 139, 216, 94, 211, 23, 218, 179, 159, 31, 198, 201, 1, 153, 89, 60, 111, 159, 53, 196, 186, 142, 71, 241, 151, 236, 131, 92, 226, 203, 2, 76, 93, 235, 95, 233, 255, 218, 61, 147, 203, 124, 85, 31, 243, 160, 173, 140, 32, 71, 228, 71, 162, 163, 236, 63, 140, 38, 166, 176, 149, 151, 32, 27, 1, 61, 140, 55, 110, 205, 253, 86, 86, 154, 173, 97, 172, 6, 153, 51, 153, 11, 162, 175, 248, 205, 187, 114, 130, 40, 247, 114, 229, 207, 4, 203, 173, 178, 98, 29, 57, 178, 176, 79, 212, 119, 45, 107, 96, 32, 62, 48, 120, 116, 165, 81, 147, 27, 66, 163, 243, 241, 4, 131, 125, 59, 79, 15, 190, 128, 154, 45, 227, 224, 6, 3, 158, 249, 127, 4, 66, 122, 69, 107, 179, 128, 184, 149, 252, 13, 95, 50, 70, 243, 181, 138, 3, 183, 160, 120, 200, 227, 67, 216, 232, 156, 31, 4, 144, 254, 50, 38, 211, 193, 162, 4, 179, 94, 6, 68, 191, 175, 205, 48, 21, 173, 96, 9, 48, 195, 165, 45, 230, 16, 50, 102, 104, 161, 136, 22, 249, 88, 191, 145, 48, 147, 140, 40, 183, 17, 151, 53, 78, 56, 115, 9, 152, 104, 211, 76, 169, 214, 74, 78, 202, 96, 227, 213], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43,
					 243, 37, 77, 126, 183, 5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84] 
			};

			let v_0_call = mock::Call::IrisProxy(Call::submit_capsule_fragment {
				data_consumer: test_data.consumer.public().clone(), 
				public_key: test_data.public_key.clone(), 
				encrypted_cfrag_data: encrypted_cfrag_0.clone()
			});

			let tx = pool_state.write().transactions.pop().unwrap();
			assert!(pool_state.read().transactions.is_empty());
			let tx = mock::Extrinsic::decode(&mut &*tx).unwrap();
			assert_eq!(tx.signature.unwrap().0, 6);
			assert_eq!(v_0_call, tx.call);
			// // And: I submit capsule fragments 
			assert_ok!(IrisProxy::submit_capsule_fragment(
				Origin::signed(validators[0].0.clone()),
				test_data.consumer.public().clone(),
				test_data.public_key.clone(),
				encrypted_cfrag_0.clone(),
			));

			let encrypted_cfrag_1 = EncryptedBox { 
				nonce: vec![102, 209, 34, 179, 214, 75, 129, 24, 44, 14, 136, 104, 179, 34, 247, 161, 168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![219, 132, 39, 23, 250, 187, 96, 234, 245, 218, 82, 27, 100, 211, 246, 36, 10, 35, 28, 213, 105, 46, 255, 240, 7, 212, 48, 8, 141, 120, 92, 12, 93, 2, 127, 34, 158, 116, 241, 61, 49, 175, 152, 59, 67, 44, 196, 187, 137, 191, 82, 99, 223, 106, 86, 140, 213, 141, 165, 91, 51, 156, 175, 197, 198, 17, 110, 217, 51, 136, 239, 141, 95, 82, 128, 77, 196, 59, 177, 187, 87, 248, 139, 137, 170, 173, 201, 35, 13, 37, 237, 138, 181, 103, 59, 111, 175, 192, 9, 179, 148, 226, 37, 46, 88, 143, 110, 46, 249, 144, 208, 21, 73, 155, 49, 41, 254, 92, 102, 194, 27, 38, 213, 213, 15, 86, 157, 116, 151, 224, 106, 248, 98, 192, 4, 54, 222, 19, 152, 83, 133, 178, 202, 228, 214, 56, 5, 249, 139, 216, 94, 211, 23, 218, 179, 159, 31, 198, 201, 1, 153, 89, 60, 111, 159, 53, 196, 186, 142, 71, 241, 151, 236, 131, 92, 226, 203, 2, 76, 93, 235, 95, 233, 255, 218, 61, 147, 203, 124, 85, 31, 243, 160, 173, 140, 32, 71, 228, 71, 162, 163, 236, 63, 140, 38, 166, 176, 149, 151, 32, 27, 1, 61, 141, 94, 118, 89, 221, 162, 153, 107, 118, 215, 101, 41, 35, 172, 224, 255, 100, 19, 217, 49, 20, 165, 183, 203, 152, 92, 123, 96, 33, 237, 130, 178, 156, 29, 57, 178, 176, 79, 212, 119, 45, 107, 96, 32, 62, 48, 120, 116, 165, 81, 147, 27, 66, 163, 243, 241, 4, 131, 125, 59, 79, 15, 190, 128, 154, 45, 8, 203, 238, 66, 246, 153, 204, 106, 244, 201, 146, 126, 103, 130, 162, 142, 132, 200, 212, 110, 115, 148, 38, 31, 254, 94, 64, 57, 184, 154, 195, 234, 95, 248, 162, 124, 202, 52, 146, 216, 196, 180, 8, 251, 250, 143, 44, 125, 73, 235, 173, 242, 229, 147, 82, 153, 4, 54, 81, 253, 244, 14, 84, 229, 114, 54, 143, 51, 28, 63, 156, 45, 168, 229, 189, 200, 239, 51, 195, 74, 37, 176, 135, 123, 196, 42, 162, 198, 5, 251, 207, 136, 202, 126, 143, 207], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43, 243, 37, 77, 126, 183, 5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84] 
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
			assert_eq!(tx.signature.unwrap().0, 7);
			assert_eq!(v_1_call, tx.call);
			// And: I submit capsule fragments 
			assert_ok!(IrisProxy::submit_capsule_fragment(
				Origin::signed(validators[1].0.clone()),
				test_data.consumer.public().clone(),
				test_data.public_key.clone(),
				encrypted_cfrag_1.clone(),
			));


			let encrypted_cfrag_2 = EncryptedBox { 
				nonce: vec![102, 209, 34, 179, 214, 75, 129, 24, 44, 14, 136, 104, 179, 34, 247, 161, 168, 16, 131, 113, 43, 29, 165, 49], 
				ciphertext: vec![107, 117, 156, 169, 113, 243, 136, 43, 106, 214, 81, 101, 177, 62, 208, 220, 11, 121, 241, 158, 163, 194, 124, 179, 167, 171, 147, 16, 176, 69, 149, 80, 117, 88, 47, 95, 47, 225, 40, 12, 169, 9, 72, 59, 29, 127, 35, 170, 105, 190, 47, 114, 215, 70, 179, 27, 37, 25, 124, 219, 84, 143, 184, 117, 61, 249, 171, 7, 219, 184, 84, 212, 128, 226, 239, 98, 54, 51, 164, 17, 97, 204, 56, 75, 89, 126, 25, 236, 7, 144, 174, 240, 216, 55, 93, 203, 32, 217, 49, 88, 66, 236, 76, 209, 184, 125, 216, 116, 228, 238, 206, 107, 36, 180, 49, 41, 254, 92, 102, 194, 27, 38, 213, 213, 15, 86, 157, 116, 151, 224, 106, 248, 98, 192, 4, 54, 222, 19, 152, 83, 133, 178, 202, 228, 214, 56, 5, 249, 139, 216, 94, 211, 23, 218, 179, 159, 31, 198, 201, 1, 153, 89, 60, 111, 159, 53, 196, 186, 142, 71, 241, 151, 236, 131, 92, 226, 203, 2, 76, 93, 235, 95, 233, 255, 218, 61, 147, 203, 124, 85, 31, 243, 160, 173, 140, 32, 71, 228, 71, 162, 163, 236, 63, 140, 38, 166, 176, 149, 151, 32, 27, 1, 61, 141, 138, 86, 173, 98, 197, 122, 7, 103, 117, 141, 160, 219, 115, 92, 12, 136, 212, 39, 38, 115, 16, 250, 255, 40, 187, 132, 2, 14, 65, 199, 45, 230, 29, 57, 178, 176, 79, 212, 119, 45, 107, 96, 32, 62, 48, 120, 116, 165, 81, 147, 27, 66, 163, 243, 241, 4, 131, 125, 59, 79, 15, 190, 128, 154, 45, 181, 191, 121, 3, 130, 165, 78, 64, 228, 191, 35, 32, 180, 16, 17, 8, 133, 184, 107, 41, 159, 133, 1, 49, 193, 80, 229, 85, 217, 108, 151, 78, 196, 199, 162, 142, 31, 53, 214, 150, 153, 58, 108, 245, 103, 18, 164, 173, 162, 237, 179, 26, 83, 85, 89, 80, 113, 93, 46, 13, 92, 176, 135, 94, 88, 27, 206, 116, 245, 118, 58, 91, 76, 17, 165, 155, 46, 65, 135, 108, 251, 154, 20, 76, 161, 244, 10, 175, 154, 35, 13, 169, 52, 63, 158, 16], 
				public_key: vec![136, 127, 175, 150, 142, 160, 194, 185, 24, 43,
					 243, 37, 77, 126, 183, 5, 114, 157, 167, 133, 183, 81, 29, 217, 53, 237, 240, 233, 111, 29, 9, 84] 
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
			assert_eq!(tx.signature.unwrap().0, 8);
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
