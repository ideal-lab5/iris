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

    let encrypted_sk = encrypt_x25519(proxy_public_key, data_owner_umbral_sk.to_string().as_bytes().to_vec());

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
    key_fragment_bytes: Vec<u8>,
) -> EncryptedFragment {
    let mut rng = ChaCha20Rng::seed_from_u64(31u64);
    let ephemeral_secret_key = BoxSecretKey::generate(&mut rng);

    let salsa_box = SalsaBox::new(&public_key, &ephemeral_secret_key);
    let nonce = SalsaBox::generate_nonce(&mut rng);
    // TODO: should probably use encrypt_in_place for safety?
    let ciphertext: Vec<u8> = salsa_box.encrypt(&nonce, &key_fragment_bytes[..]).unwrap().to_vec();

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

pub fn decrypt(
    ciphertext: Vec<u8>,
    x25519_sk: BoxSecretKey, // supplied to the rpc as an argument
    data_owner_public_key: PublicKey,
    consumer_secret_key: SecretKey,
    encrypted_capsule_fragments: Vec<EncryptedFragment>,
    capsule: Capsule,
) -> Result<Vec<u8>, ReencryptionError>  {
    // for each encrypted capsule fragment, we need to decrypt it
    let verified_capsule_fragments: Vec<VerifiedCapsuleFrag> = 
        convert_encrypted_capsules(encrypted_capsule_fragments, x25519_sk.clone());
    match decrypt_reencrypted(
        &consumer_secret_key, &data_owner_public_key, &capsule, verified_capsule_fragments, &ciphertext
    ) {
        Ok(result) => {
            return Ok(result.to_vec());
        }
        Err(e) => {
            return Err(e);
        }
    }
}

fn convert_encrypted_capsules(
    encrypted_capsule_frags: Vec<EncryptedFragment>,
    x25519_sk: BoxSecretKey,
) -> Vec<VerifiedCapsuleFrag> {
    encrypted_capsule_frags.iter().map(|enc_cap_frag| {
        let raw_pk = enc_cap_frag.public_key.clone();
        let pk_slice = slice_to_array_32(&raw_pk).unwrap();
        let pk = BoxPublicKey::from(*pk_slice);
        let decrypted_capsule_vec = decrypt_x25519(
            pk,
            x25519_sk.clone(),
            enc_cap_frag.ciphertext.clone(),
            enc_cap_frag.nonce.clone(),
        );
        VerifiedCapsuleFrag::from_verified_bytes(decrypted_capsule_vec).unwrap()
    }).collect::<Vec<_>>()
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
) -> Vec<u8> {
    let salsa_box = SalsaBox::new(&sender_public_key, &receiver_secret_key);
    // GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>, B0>>
    let gen_array = generic_array::GenericArray::clone_from_slice(nonce_bytes.as_slice());
    salsa_box.decrypt(&gen_array, Payload {
        msg: &ciphertext,
        aad: b"".as_ref(),
    }).unwrap()
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
	let (p, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];

	let mut rng = ChaCha20Rng::seed_from_u64(31u64);
	let sk = SecretKey::random_with_rng(rng.clone());
	let pk = sk.public_key();

	let plaintext = "plaintext".as_bytes();
	let shares: usize = 3;
	let threshold: usize = 3;

	let result = encrypt(plaintext, shares, threshold, pk).unwrap();
	assert_eq!(49, result.3.len());
}

#[test]
fn can_encrypt_x25519() {
	// Given: I am a valid node with a positive balance
	let (p, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];

	let test_vec = "test".as_bytes().to_vec();
	let mut rng = ChaCha20Rng::seed_from_u64(31u64);
	let sk = BoxSecretKey::generate(&mut rng);
	let pk = sk.public_key();

	let encrypted_frag = encrypt_x25519(pk, test_vec);
	assert_eq!(true, encrypted_frag.nonce.len() > 0);
	assert_eq!(true, encrypted_frag.ciphertext.len() > 0);
	assert_eq!(true, encrypted_frag.public_key.len() > 0);
}
