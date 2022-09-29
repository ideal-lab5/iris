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
use codec::{Decode, Encode, CompactAs, HasCompact, Compact};
use sp_core::Bytes;
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;
use scale_info::TypeInfo;
use frame_support::pallet_prelude::MaxEncodedLen;


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

#[derive(PartialEq, Eq, Encode, Decode, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct EncryptionResult {
	pub public_key: Bytes,
	pub ciphertext: Bytes,
}

#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo, Clone)]
pub struct EncryptedFragment {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub fn encrypt_crypto_box(
    recipient_public_key: BoxPublicKey, 
    sender_secret_key: BoxSecretKey, 
    plaintext: Vec<u8>
) -> EncryptedFragment {
    let mut rng = ChaCha20Rng::seed_from_u64(31u64);
    let salsa_box = SalsaBox::new(&recipient_public_key, &sender_secret_key);
    let nonce = SalsaBox::generate_nonce(&mut rng);
    let ciphertext: Vec<u8> = salsa_box.encrypt(&nonce, Payload {
        msg: &plaintext,
        aad: b"".as_ref(),
    }).unwrap().to_vec();
    EncryptedFragment{ 
        nonce: nonce.as_slice().to_vec(),
        ciphertext: ciphertext,
        public_key: sender_secret_key.public_key().as_bytes().to_vec()
    }
}

// pub fn encrypt_crypto_box_ephemeral(public_key_bytes: Vec<u8>, plaintext: Vec<u8>) -> EncryptedFragment {
//     let mut rng = ChaCha20Rng::seed_from_u64(31u64);
//     let ephemeral_secret_key = BoxSecretKey::generate(&mut rng);
//     let pubkey_slice_32 = Self::slice_to_array_32(public_key_bytes.as_slice()).unwrap();
//     let public_key = BoxPublicKey::from(*pubkey_slice_32);

//     let salsa_box = SalsaBox::new(&public_key, &plaintext);
//     let nonce = SalsaBox::generate_nonce(&mut rng);
//     let ciphertext: Vec<u8> = salsa_box.encrypt(&nonce, &p[..]).unwrap().to_vec();

//     // to decrypt, the account associated with the public_key needs to know:
//     // (nonce, ciphertext, ephermeral public_key)
//     // so we should return some object? like...
//     EncryptedFragment{ 
//         nonce: nonce.as_slice().to_vec(),
//         ciphertext: ciphertext,
//         public_key: ephemeral_secret_key.public_key().as_bytes().to_vec()
//     }
// }

pub fn slice_to_array_32(slice: &[u8]) -> Option<&[u8; 32]> {
    if slice.len() == 32 {
        let ptr = slice.as_ptr() as *const [u8; 32];
        unsafe {Some(&*ptr)}
    } else {
        None
    }
}