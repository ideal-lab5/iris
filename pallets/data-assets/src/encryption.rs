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

///
/// Functions for performing encryption and decryption
/// 
use scale_info::prelude::string::ToString;
use sp_std::prelude::*;
use umbral_pre::*;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::SeedableRng,
};
use crypto_box::{
    aead::{ AeadCore, Aead },
	SalsaBox, PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, Nonce,
};
use iris_primitives::EncryptedFragment;

/// generates a new keypair and uses it to encrypt the plaintext
/// also encrypts the secret key with itself and generates 'shares' keyfragments
/// of which 'threshold' pieces are needed to re-encrypt the encrypted secret key
///
/// * 'plaintext': the plaintext to encrypt
/// * 'shares': The number of shares to create (i.e. key fragments to create and distribute)
/// * 'threshold': The number of key fragments needed to re-encrypt the encrypted secret key
/// * 'owner': The account id of the address that owns the plaintext
///
/// return encryption artifacts (Capsule, ciphertext, and public key) if successful, otherwise returns None
///
pub fn encrypt(
    plaintext: &[u8], 
    shares: usize, 
    threshold: usize,
) -> Result<(Vec<VerifiedKeyFrag>, Capsule, Capsule, Vec<u8>, Vec<u8>, PublicKey), EncryptionError> {
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
        },
    };

    // encrypt the secret key
    let (sk_capsule, sk_ciphertext) = match umbral_pre::encrypt_with_rng(
        &mut rng.clone(), &data_owner_umbral_pk, data_owner_umbral_sk.to_string().as_bytes(),
    ) {
        Ok((capsule, ciphertext)) => (capsule, ciphertext),
        Err(error) => {
            return Err(error);
        },
    };

    let signer = Signer::new(SecretKey::random_with_rng(rng.clone()));

    let verified_kfrags = generate_kfrags_with_rng(
        &mut rng.clone(), &data_owner_umbral_sk, &data_owner_umbral_pk, &signer, threshold, shares, true, true
    );

    Ok((
        verified_kfrags.into_vec(), 
        data_capsule, 
        sk_capsule, 
        data_ciphertext.to_vec(), 
        sk_ciphertext.to_vec(), 
        data_owner_umbral_pk
    ))
}

///
/// Encrypt the bytes with an ephemeral secret key and your provided public key.
/// This performs asymmetric encryption
///
pub fn encrypt_kfrag_ephemeral(public_key: BoxPublicKey, key_fragment_bytes: Vec<u8>) -> EncryptedFragment {
    let mut rng = ChaCha20Rng::seed_from_u64(31u64);
    let ephemeral_secret_key = BoxSecretKey::generate(&mut rng);

    let salsa_box = SalsaBox::new(&public_key, &ephemeral_secret_key);
    let nonce = SalsaBox::generate_nonce(&mut rng);
    let ciphertext: Vec<u8> = salsa_box.encrypt(&nonce, &key_fragment_bytes[..]).unwrap().to_vec();

    // TODO: really need to make it clearer exactly which public key this is
    // the public key should be the pk of the ephemeral secret key
    EncryptedFragment{ 
        nonce: nonce.as_slice().to_vec(),
        ciphertext: ciphertext,
        public_key: ephemeral_secret_key.public_key().as_bytes().to_vec()
    }
}

// pub fn decrypt() {
//     let plaintext = umbral_pre::decrypt_reencrypted(
//         &my_sk, &data_owner_pk, &sk_capsule, [verified_kfrags], &sk_ciphertext
//     );
// }

mod tests {
    use super::*;
    use frame_support::{assert_ok, assert_err};
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
    fn encryption_can_encrypt() {
        // Given: I am a valid node with a positive balance
        let (p, _) = sp_core::sr25519::Pair::generate();
        let pairs = vec![(p.clone().public(), 10)];

        let plaintext = "plaintext".as_bytes();
        let shares: usize = 3;
        let threshold: usize = 3;

        let result = encrypt(plaintext, shares, threshold).unwrap();
        assert_eq!(49, result.3.len());
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

        let encrypted_frag = encrypt_kfrag_ephemeral(pk, test_vec);
        assert_eq!(true, encrypted_frag.nonce.len() > 0);
        assert_eq!(true, encrypted_frag.ciphertext.len() > 0);
        assert_eq!(true, encrypted_frag.public_key.len() > 0);
    }
}