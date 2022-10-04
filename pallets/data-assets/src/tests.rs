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
use sp_runtime::testing::UintAuthorityId;
use sp_core::{
	offchain::{testing, OffchainWorkerExt, TransactionPoolExt, OffchainDbExt}
};
use umbral_pre::*;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::SeedableRng,
};
use crypto_box::{
    aead::{ AeadCore, Aead },
	SalsaBox, PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, Nonce,
};

#[test]
fn data_assets_initial_state() {
	new_test_ext(validators()).execute_with(|| {
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

	new_test_ext_funded(pairs, validators()).execute_with(|| {
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
fn data_assets_can_submit_capsule_and_kfrags() {
	// Given: I am a valid node with a positive balance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let (g, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];
	
	let test_vec = "test".as_bytes().to_vec();
	let encrypted_kfrag = EncryptedFragment {
		nonce: test_vec.clone(),
		ciphertext: test_vec.clone(),
		public_key: test_vec.clone(),
	};

	let kfrag_assignments = vec![(p.public().clone(), encrypted_kfrag.clone())];

	new_test_ext_funded(pairs, validators()).execute_with(|| {
		// When: I submit key fragments
		assert_ok!(DataAssets::submit_capsule_and_kfrags(
			Origin::signed(p.clone().public()),
			p.clone().public(),
			test_vec.clone(),
			test_vec.clone(),
			test_vec.clone(),
			test_vec.clone(),
			kfrag_assignments,
		));

		// Then: A new entry is added to the fragments map
		let assigned_kfrag = Fragments::<Test>::get(test_vec.clone(), p.public().clone());
		assert_eq!(assigned_kfrag, Some(encrypted_kfrag.clone()));

		let frag_holders = FragmentOwnerSet::<Test>::get(test_vec.clone());
		assert_eq!(1, frag_holders.len());
		assert_eq!(vec![p.public().clone()], frag_holders);

		let secret_data = Capsules::<Test>::get(test_vec.clone()).unwrap();
		assert_eq!(test_vec.clone(), secret_data.data_capsule);
		assert_eq!(test_vec.clone(), secret_data.sk_capsule);
		assert_eq!(test_vec.clone(), secret_data.sk_ciphertext);

		let pk = IngestionStaging::<Test>::get(p.public().clone()).unwrap();
		assert_eq!(test_vec.clone(), pk);
	}); 
}

#[test]
fn can_encrypt_kfrag_ephemeral() {
	// Given: I am a valid node with a positive balance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];

	let test_vec = "test".as_bytes().to_vec();
	let mut rng = ChaCha20Rng::seed_from_u64(31u64);
	let sk = BoxSecretKey::generate(&mut rng);
	let pk = sk.public_key();

	let encrypted_frag = DataAssets::encrypt_kfrag_ephemeral(pk, test_vec);
	assert_eq!(true, encrypted_frag.nonce.len() > 0);
	assert_eq!(true, encrypted_frag.ciphertext.len() > 0);
	assert_eq!(true, encrypted_frag.public_key.len() > 0);
}

#[test]
fn encryption_can_encrypt() {
	// Given: I am a valid node with a positive balance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];

	let plaintext = "plaintext".as_bytes();
	let shares: usize = 3;
	let threshold: usize = 3;

	let mut t = new_test_ext_funded(pairs, validators());
	let (offchain, state) = testing::TestOffchainExt::new();
	let (pool, _) = testing::TestTransactionPoolExt::new();
	t.register_extension(OffchainWorkerExt::new(offchain));
	t.register_extension(TransactionPoolExt::new(pool));

	t.execute_with(|| {
		let ciphertext = DataAssets::do_encrypt(plaintext, shares, threshold, p.public().clone()).unwrap();
		assert_eq!(49, ciphertext.len());
	});
}

#[test]
fn encryption_fails_when_kfrag_shares_exceed_available_validators() {
	// Given: I am a valid node with a positive balance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];

	let plaintext = "plaintext".as_bytes();
	let shares: usize = 5;
	let threshold: usize = 3;

	let mut t = new_test_ext_funded(pairs, validators());
	let (offchain, state) = testing::TestOffchainExt::new();
	let (pool, _) = testing::TestTransactionPoolExt::new();
	t.register_extension(OffchainWorkerExt::new(offchain));
	t.register_extension(TransactionPoolExt::new(pool));

	t.execute_with(|| {
		let ciphertext = DataAssets::do_encrypt(plaintext, shares, threshold, p.public().clone()).unwrap();
		assert_eq!(0, ciphertext.len());
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

// TODO: Test QueueProvider functions
// TODO: Test ResultsHandler:create_asset_class function