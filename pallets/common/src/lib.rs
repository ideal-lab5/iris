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
use codec::{Decode, Encode};
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;
use scale_info::TypeInfo;

use crypto_box::{
    aead::{Aead, AeadCore, Payload},
	SalsaBox, PublicKey as BoxPublicKey, SecretKey as BoxSecretKey,
};
use rand_chacha::{
	ChaCha20Rng,
	rand_core::SeedableRng,
};

#[derive(Eq, Ord, PartialOrd, Encode, Decode, RuntimeDebug, PartialEq, TypeInfo, Clone)]
pub struct IngestionCommand<AccountId, Balance> {
    /// the owner of the data to be ingested (i.e. the caller)
    pub owner: AccountId,
    /// the CID of the data to be ingested
    pub cid: Vec<u8>,
    /// the multiaddress of the ipfs node where the data already exists
    pub multiaddress: Vec<u8>,
    /// the balance used to create an asset class and pay a proxy node
    pub balance: Balance,
}

#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo, Clone)]
pub struct EncryptedBox {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub public_key: Vec<u8>,
}

///
/// Encrypt the bytes with an ephemeral secret key and your provided public key.
///
pub fn encrypt_x25519(
    public_key: BoxPublicKey, 
    plaintext: Vec<u8>,
) -> EncryptedBox {
    let mut rng = ChaCha20Rng::seed_from_u64(31u64);
    let ephemeral_secret_key = BoxSecretKey::generate(&mut rng);

    let salsa_box = SalsaBox::new(&public_key, &ephemeral_secret_key);
    let nonce = SalsaBox::generate_nonce(&mut rng);
    // TODO: should probably use encrypt_in_place for safety?
    let ciphertext: Vec<u8> = salsa_box.encrypt(&nonce, &plaintext[..]).unwrap().to_vec();

    EncryptedBox { 
        nonce: nonce.as_slice().to_vec(),
        ciphertext,
        public_key: ephemeral_secret_key.public_key().as_bytes().to_vec()
    }
}

/*
    DECRYPTION FUNCTIONS
*/

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

/*
    UTILITY FUNCTIONS
*/

/// Convert a public key encoded as a vector of u8
/// to a BoxPublicKey type required for encryption and decryption
pub fn vec_to_box_public_key(pk_vec: &[u8]) -> BoxPublicKey {
    // TODO: error handling
    let pk_array = slice_to_array_32(pk_vec).unwrap();
    BoxPublicKey::from(*pk_array)
}

/// Convert a slice of u8 to an array of u8 of size 32
/// 
/// * `slice`: The slize to convert
/// 
pub fn slice_to_array_32(slice: &[u8]) -> Option<&[u8; 32]> {
    if slice.len() == 32 {
        let ptr = slice.as_ptr() as *const [u8; 32];
        unsafe {Some(&*ptr)}
    } else {
        None
    }
}

/*
TESTS
*/

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