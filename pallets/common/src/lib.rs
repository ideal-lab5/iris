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
#![cfg_attr(not(feature = "std"), no_std)]

// use std::fmt;
use codec::{Decode, Encode, CompactAs, HasCompact, Compact, alloc::string::ToString};
use sp_core::Bytes;
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;
use scale_info::TypeInfo;
use frame_support::pallet_prelude::MaxEncodedLen;

use umbral_pre::*;
use crypto_box::{
    aead::{Aead, AeadCore, Payload},
	SalsaBox, PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, Nonce,
};
use rand_chacha::{
	ChaCha20Rng,
	rand_core::SeedableRng,
};

#[cfg(feature = "std")]
use sp_rpc::number::NumberOrHex;

#[cfg(feature = "std")]
use serde::{
    Deserialize, 
    Serialize,
    de::{Visitor},
};

#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub struct ReencryptionRequest<AccountId> {
    pub caller: AccountId,
    pub data_public_key: Vec<u8>,
    pub verifying_public_key: Vec<u8>,
    pub caller_public_key: Vec<u8>,
}

#[derive(Eq, Ord, PartialOrd, Encode, Decode, RuntimeDebug, PartialEq, TypeInfo, Clone)]
pub struct EjectionCommand<AccountId, AssetId> {
    pub asset_id: AssetId,
    pub caller: AccountId,
}

#[derive(Eq, Ord, PartialOrd, Encode, Decode, RuntimeDebug, PartialEq, TypeInfo, Clone)]
pub struct IngestionCommand<AccountId, Balance> {
    /// the owner of the data to be ingested (i.e. the caller)
    pub owner: AccountId,
    /// the CID of the data to be ingested
    pub cid: Vec<u8>,
    /// the multiaddress of the ipfs node where the data already exists
    pub multiaddress: Vec<u8>,
    /// a 'self-reported' estimated size of data to be transferred
    /// the true data size can only be known after querying the OCC within the OCW
    pub estimated_size_gb: u128,
    /// the id of the dataspace to associate the asset class with
    // pub dataspace_id: AssetId,
    /// the balance used to create an asset class and pay a proxy node
    pub balance: Balance,
}

// needed? I don't think this is used.
#[derive(Eq, Ord, PartialOrd, Encode, Decode, RuntimeDebug, PartialEq, TypeInfo, Clone, Copy, MaxEncodedLen, Default)]
pub struct AssetId<T: Copy> {
    // #[codec(compact)]
    pub id: T,
}

#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo, Clone)]
pub struct EncryptedFragment {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub public_key: Vec<u8>,
}

/*
    ENCRYPTION FUNCTIONS
*/

/// generates a new keypair and uses it to encrypt the plaintext
/// also encrypts the secret key with itself and generates 'shares' keyfragments
/// of which 'threshold' pieces are needed to re-encrypt the encrypted secret key
///
/// * 'plaintext': the plaintext to encrypt
/// * 'shares': The number of shares to create (i.e. key fragments to create and distribute)
/// * 'threshold': The number of key fragments needed to re-encrypt the encrypted secret key
/// * 'proxy_public_key': A public key of a node who will be allowed to reencrypt the secret
///
/// return encryption artifacts (Capsule, ciphertext, and public key) if successful, otherwise returns None
///
pub fn encrypt(
    plaintext: &[u8], 
    shares: usize, 
    threshold: usize,
    proxy_public_key: BoxPublicKey,
) -> Result<(Capsule, Vec<u8>, PublicKey, EncryptedFragment), EncryptionError> {
    let mut rng = ChaCha20Rng::seed_from_u64(17u64);
    // generate keys
    let data_owner_umbral_sk = SecretKey::random_with_rng(rng.clone());
    let data_owner_umbral_pk = data_owner_umbral_sk.public_key();

    let (data_capsule, data_ciphertext) = match umbral_pre::encrypt_with_rng(
        &mut rng.clone(), &data_owner_umbral_pk, plaintext)
    {
        Ok((capsule, ciphertext)) => (capsule, ciphertext),
        Err(error) => {
            return Err(error);
        }
    };

    let secret_key_bytes = data_owner_umbral_sk
        .to_secret_array()
        .as_secret()
        .to_vec();
    let encrypted_sk = encrypt_x25519(
        proxy_public_key, 
        secret_key_bytes,
    );

    Ok((
        data_capsule,
        data_ciphertext.to_vec(),
        data_owner_umbral_pk,
        encrypted_sk,
    ))
}

///
/// Encrypt the bytes with an ephemeral secret key and your provided public key.
/// This performs asymmetric encryption
///
pub fn encrypt_x25519(
    public_key: BoxPublicKey, 
    plaintext: Vec<u8>,
) -> EncryptedFragment {
    let mut rng = ChaCha20Rng::seed_from_u64(31u64);
    let ephemeral_secret_key = BoxSecretKey::generate(&mut rng);

    let salsa_box = SalsaBox::new(&public_key, &ephemeral_secret_key);
    let nonce = SalsaBox::generate_nonce(&mut rng);
    // TODO: should probably use encrypt_in_place for safety?
    let ciphertext: Vec<u8> = salsa_box.encrypt(&nonce, &plaintext[..]).unwrap().to_vec();

    // TODO: really need to make it clearer exactly which public key this is
    // the public key should be the pk of the ephemeral secret key
    EncryptedFragment{ 
        nonce: nonce.as_slice().to_vec(),
        ciphertext: ciphertext,
        public_key: ephemeral_secret_key.public_key().as_bytes().to_vec()
    }
}

/*
    DECRYPTION FUNCTIONS
*/

/// A helper functio to decrypt and convert encrypted capsule fragments back to capsule fragments
pub fn convert_encrypted_capsules(
    encrypted_capsule_frags: Vec<EncryptedFragment>,
    x25519_sk: BoxSecretKey,
) -> Result<Vec<CapsuleFrag>, crypto_box::aead::Error> {
    let mut capsules = Vec::new();
    for enc_cap_frag in encrypted_capsule_frags.iter() {
        let raw_pk = enc_cap_frag.public_key.clone();
        let pk_slice = slice_to_array_32(&raw_pk).unwrap();
        let pk = BoxPublicKey::from(*pk_slice);
        let decrypted_capsule_vec = decrypt_x25519(
            pk,
            x25519_sk.clone(),
            enc_cap_frag.ciphertext.clone(),
            enc_cap_frag.nonce.clone(),
        )?;
        capsules.push(CapsuleFrag::from_bytes(decrypted_capsule_vec).unwrap());
    }
    Ok(capsules)    
}

/// Decrypt message encrypted with X25519 keys
/// 
/// * `sender_public_key`: The X25519 public key whose corresponding secret key encrypted the ciphertext.
/// * `receiver_secret_key`: The X25519 secret key for who the ciphertext was encrypted.
/// * `ciphertext`: The encrypted ciphertext as bytes.
/// *  `nonce_bytes`: The nonce used when encrypting the plaintext, as bytes.
/// 
pub fn decrypt_x25519(
    sender_public_key: BoxPublicKey, 
    receiver_secret_key: BoxSecretKey,
    ciphertext: Vec<u8>,
    nonce_bytes: Vec<u8>,
) -> Result<Vec<u8>, crypto_box::aead::Error> {
    let salsa_box = SalsaBox::new(&sender_public_key, &receiver_secret_key);
    // GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>, B0>>
    let gen_array = generic_array::GenericArray::clone_from_slice(nonce_bytes.as_slice());
    salsa_box.decrypt(&gen_array, Payload {
        msg: &ciphertext,
        aad: b"".as_ref(),
    })
}


pub fn slice_to_array_32(slice: &[u8]) -> Option<&[u8; 32]> {
    if slice.len() == 32 {
        let ptr = slice.as_ptr() as *const [u8; 32];
        unsafe {Some(&*ptr)}
    } else {
        None
    }
}
/*
	encryption tests
*/
#[test]
fn encryption_can_encrypt() {
	// Given: I am a valid node with a positive balance
    let mut rng = ChaCha20Rng::seed_from_u64(31u64);
	let sk = BoxSecretKey::generate(&mut rng);
	let pk = sk.public_key();

	let plaintext = "plaintext".as_bytes();
	let shares: usize = 3;
	let threshold: usize = 3;

	let result = encrypt(plaintext, shares, threshold, pk).unwrap();
	assert_eq!(49, result.1.len());
}

#[test]
fn can_encrypt_x25519() {
	let test_vec = "test".as_bytes().to_vec();
	let mut rng = ChaCha20Rng::seed_from_u64(31u64);
	let sk = BoxSecretKey::generate(&mut rng);
	let pk = sk.public_key();

	let encrypted_frag = encrypt_x25519(pk, test_vec);
	assert_eq!(true, encrypted_frag.nonce.len() > 0);
	assert_eq!(true, encrypted_frag.ciphertext.len() > 0);
	assert_eq!(true, encrypted_frag.public_key.len() > 0);
}

#[test]
fn test_can_decrypt_x25519_using_output_of_encrypt_x25519() {
    // Given: I am a valid node with a positive balance
    let plaintext = "test".as_bytes().to_vec();
    let mut rng = ChaCha20Rng::seed_from_u64(31u64);
    let sk = BoxSecretKey::generate(&mut rng);
    let pk = sk.public_key();

    let encrypted = encrypt_x25519(pk.clone(), plaintext.clone());

    let pk_tmp = encrypted.public_key.clone();
    let pk_slice = slice_to_array_32(&pk_tmp).unwrap();
    let recovered_pk = BoxPublicKey::from(*pk_slice);

    match decrypt_x25519(
        recovered_pk, sk.clone(), encrypted.ciphertext.clone(), encrypted.nonce.clone(),
    ) {
        Ok(recovered_plaintext) => {
            assert_eq!(plaintext.clone(), recovered_plaintext.clone());
        },
        Err(e) => {
            panic!("{:?}", e);
        }
    }
}

#[test]
fn iris_protocol() {
    // Key Generation (on Alice's side)
    let mut rng = ChaCha20Rng::seed_from_u64(17u64);

    // generate keys for each actor
    // for each we generate two sets of keys, one using umbral and one using crypto box
    // to distinguish between them, I'll use a 'u' prefix for umbral keys, 'b' for crypto box

    // the data owner Olivia generates keys
    // we'll refer to her first key as the 'root' key, since it is ultimately what's needed to decrypt data
    let u_root_sk = SecretKey::random_with_rng(&mut rng);
    let u_root_pk = u_root_sk.public_key();
    let b_olivia_sk = BoxSecretKey::generate(&mut rng);
    let b_olivia_pk = b_olivia_sk.public_key();

    // the proxy, Paul
    let u_paul_sk = SecretKey::random_with_rng(&mut rng);
    let u_paul_pk = u_paul_sk.public_key();
    let b_paul_sk = BoxSecretKey::generate(&mut rng);
    let b_paul_pk = b_paul_sk.public_key();

    // the data consumer Charlie
    let charlie_sk = SecretKey::random_with_rng(&mut rng);
    let charlie_pk = charlie_sk.public_key();
    let b_charlie_sk = BoxSecretKey::generate(&mut rng);
    let b_charlie_pk = b_charlie_sk.public_key();

    // setup validators
    // the validator victor_0
    let victor_0_sk = SecretKey::random_with_rng(&mut rng);
    let victor_0_pk = victor_0_sk.public_key();
    let b_victor_0_sk = BoxSecretKey::generate(&mut rng);
    let b_victor_0_pk = b_victor_0_sk.public_key();
    // the validator victor_1
    let victor_1_sk = SecretKey::random_with_rng(&mut rng);
    let victor_1_pk = victor_1_sk.public_key();
    let b_victor_1_sk = BoxSecretKey::generate(&mut rng);
    let b_victor_1_pk = b_victor_1_sk.public_key();
    // the validator victor_2
    let victor_2_sk = SecretKey::random_with_rng(&mut rng);
    let victor_2_pk = victor_2_sk.public_key();
    let b_victor_2_sk = BoxSecretKey::generate(&mut rng);
    let b_victor_2_pk = b_victor_2_sk.public_key();

    // the signer/verifying pk
    let signer = Signer::new(SecretKey::random_with_rng(&mut rng));
    let verifying_pk = signer.verifying_key();

    // Olivia encrypts some data
    let plaintext = b"it was a dark and stormy night...";
    let (capsule, ciphertext) = encrypt_with_rng(&mut rng, &u_root_pk, plaintext).unwrap();

    // olivia encrypts the secret key u_data_sk using for paulusing his public key, b_paul_pk
    let secret_key_bytes = u_root_sk
        .to_secret_array()
        .as_secret()
        .to_vec();
    // now this box can be shared publicly and only Paul can decrypt it
    let public_data_sk_box = encrypt_x25519(
        b_paul_pk.clone(),
        secret_key_bytes
    );

    let tmp = public_data_sk_box.public_key.clone();
	let pk_array = slice_to_array_32(&tmp).unwrap();
    let public_data_sk_box_pk = BoxPublicKey::from(*pk_array);

    let shares = 3; // how many fragments to create
    let threshold = 2; // how many should be enough to decrypt
    // now, Paul want to generate new key fragments and delegate decryption rights to another actor
    let paul_decrypted_data_sk_bytes = decrypt_x25519(
        public_data_sk_box_pk.clone(),
        b_paul_sk,
        public_data_sk_box.ciphertext.clone(),
        public_data_sk_box.nonce.clone(),
    ).unwrap();
    // convert the new vec to a secret key
    // let tmp_sk = paul_decrypted_data_sk_bytes.clone();
	// let sk_array = iris_primitives::slice_to_array_32(&tmp_sk).unwrap();
    let u_paul_decrypted_root_sk = SecretKey::from_bytes(paul_decrypted_data_sk_bytes.clone()).unwrap();
    // assert_eq!(u_paul_decrypted_root_sk, u_root_sk);

    // generate kfrags for Charlie
    let kfrags = generate_kfrags_with_rng(
        &mut rng, 
        &u_paul_decrypted_root_sk, 
        &charlie_pk.clone(), 
        &signer, 
        threshold, shares, 
        true, true
    );

    // for each kfrag, Paul chooses a validator and encrypts the key fragment with their public key
    let kfrag_0_box = encrypt_x25519(
        b_victor_0_pk.clone(),
        kfrags[0].clone().unverify().to_array().as_slice().to_vec(),
    );
    let kfrag_1_box = encrypt_x25519(
        b_victor_1_pk.clone(),
        kfrags[1].clone().unverify().to_array().as_slice().to_vec()
    );
    let kfrag_2_box = encrypt_x25519(
        b_victor_2_pk.clone(),
        kfrags[2].clone().unverify().to_array().as_slice().to_vec()
    );

    // Now each validator decrypts the kfrag performs re-encryption on the capsule using the kfrag provided by Paul,
    // obtaining this way a "capsule fragment", or cfrag.
    let kfrag_0_box_pk_tmp = kfrag_0_box.public_key.clone();
	let kfrag_0_pk_array = slice_to_array_32(&kfrag_0_box_pk_tmp).unwrap();
    let kfrag_0_pk = BoxPublicKey::from(*kfrag_0_pk_array);
    let recovered_kfrag_0_data = decrypt_x25519(
        kfrag_0_pk.clone(),
        b_victor_0_sk.clone(),
        kfrag_0_box.ciphertext.clone(),
        kfrag_0_box.nonce.clone(),
    ).unwrap();

    let kfrag_1_box_pk_tmp = kfrag_1_box.public_key.clone();
	let kfrag_1_pk_array = slice_to_array_32(&kfrag_1_box_pk_tmp).unwrap();
    let kfrag_1_pk = BoxPublicKey::from(*kfrag_1_pk_array);
    let recovered_kfrag_1_data = decrypt_x25519(
        kfrag_1_pk.clone(),
        b_victor_1_sk.clone(),
        kfrag_1_box.ciphertext.clone(),
        kfrag_1_box.nonce.clone(),
    ).unwrap();

    let kfrag_2_box_pk_tmp = kfrag_2_box.public_key.clone();
	let kfrag_2_pk_array = slice_to_array_32(&kfrag_2_box_pk_tmp).unwrap();
    let kfrag_2_pk = BoxPublicKey::from(*kfrag_2_pk_array);
    let recovered_kfrag_2_data = decrypt_x25519(
        kfrag_2_pk.clone(),
        b_victor_2_sk.clone(),
        kfrag_2_box.ciphertext.clone(),
        kfrag_2_box.nonce.clone(),
    ).unwrap();

    let recovered_kfrag_0 = KeyFrag::from_bytes(recovered_kfrag_0_data).unwrap();
    let recovered_kfrag_1 = KeyFrag::from_bytes(recovered_kfrag_1_data).unwrap();
    let recovered_kfrag_2 = KeyFrag::from_bytes(recovered_kfrag_2_data).unwrap();

    // finally each validator encrypts the capsule fragment for Charlie
    // we only require two cfrags
    // Victor 0
    let verified_kfrag0 = recovered_kfrag_0.verify(&verifying_pk, Some(&u_root_pk), Some(&charlie_pk)).unwrap();
    let verified_cfrag0 = reencrypt_with_rng(&mut rng, &capsule, verified_kfrag0);
    let encrypted_cfrag_0_box = encrypt_x25519(
        b_charlie_pk.clone(),
        verified_cfrag0.to_array().as_slice().to_vec(),
    );

    // Victor 1
    let verified_kfrag1 = recovered_kfrag_1.verify(&verifying_pk, Some(&u_root_pk), Some(&charlie_pk)).unwrap();
    let verified_cfrag1 = reencrypt_with_rng(&mut rng, &capsule, verified_kfrag1);
    let encrypted_cfrag_1_box = encrypt_x25519(
        b_charlie_pk.clone(),
        verified_cfrag1.to_array().as_slice().to_vec(),
    );

    // now charlie collects each encrypted cfrag, decrypts them, and converts them to CapsuleFrags
    let cfrag_0_box_pk_tmp = encrypted_cfrag_0_box.public_key.clone();
	let cfrag_0_pk_array = slice_to_array_32(&cfrag_0_box_pk_tmp).unwrap();
    let cfrag_0_pk = BoxPublicKey::from(*kfrag_0_pk_array);
    let recovered_cfrag_0_bytes = decrypt_x25519(
        cfrag_0_pk.clone(),
        b_charlie_sk.clone(),
        encrypted_cfrag_0_box.ciphertext.clone(),
        encrypted_cfrag_0_box.nonce.clone(),
    ).unwrap();

    let cfrag_1_box_pk_tmp = encrypted_cfrag_1_box.public_key.clone();
	let cfrag_1_pk_array = slice_to_array_32(&cfrag_1_box_pk_tmp).unwrap();
    let cfrag_1_pk = BoxPublicKey::from(*cfrag_1_pk_array);
    let recovered_cfrag_1_bytes = decrypt_x25519(
        cfrag_1_pk.clone(),
        b_charlie_sk.clone(),
        encrypted_cfrag_1_box.ciphertext.clone(),
        encrypted_cfrag_1_box.nonce.clone(),
    ).unwrap();
    
    // Simulate network transfer
    let cfrag0 = CapsuleFrag::from_bytes(&recovered_cfrag_0_bytes).unwrap();
    let cfrag1 = CapsuleFrag::from_bytes(&recovered_cfrag_1_bytes).unwrap();

    // Finally, Bob opens the capsule by using at least `threshold` cfrags,
    // and then decrypts the re-encrypted ciphertext.

    // Bob must check that cfrags are valid
    let verified_cfrag0 = cfrag0
        .verify(&capsule, &verifying_pk, &u_root_pk, &charlie_pk)
        .unwrap();
    let verified_cfrag1 = cfrag1
        .verify(&capsule, &verifying_pk, &u_root_pk, &charlie_pk)
        .unwrap();

    let plaintext_bob = decrypt_reencrypted(
        &charlie_sk, &u_root_pk, &capsule, [verified_cfrag0, verified_cfrag1], &ciphertext).unwrap();
    assert_eq!(&plaintext_bob as &[u8], plaintext);
}

// fn choose_kfrag_holders(
//     key_fragments: Vec<VerifiedKeyFrag>,
//     candidates: Vec<(T::AccountId, Vec<u8>)>,
// ) -> Vec<(T::AccountId, EncryptedFragment)> {
//     let mut assignments = Vec::new();
//     let rng = ChaCha20Rng::seed_from_u64(17u64);
//     for i in vec![0, required_authorities_count] {
//         let candidate = candidates[i].clone();
//         match iris_primitives::slice_to_array_32(&candidate.1) {
//             Some(pk_slice) => {
//                 let pk = BoxPublicKey::from(*pk_slice);
//                 let key_fragment = key_fragments[i].clone()
//                     .unverify()
//                     .to_array()
//                     .as_slice()
//                     .to_vec();
//                 let encrypted_kfrag_data = iris_primitives::encrypt_x25519(
//                     pk.clone(), key_fragment,
//                 );
//                 assignments.push((candidate.0.clone(), encrypted_kfrag_data.clone()));
//             },
//             None => {
//                 // idk yet
//             }
//         }
//     }
//     assignments
// }