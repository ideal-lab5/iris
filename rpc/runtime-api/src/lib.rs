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

//! Runtime API definition for data ingestion and ejection via proxy nodes

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use sp_core::Bytes;
use sp_std::vec::Vec;
use scale_info::TypeInfo;

use codec::Codec;
use sp_runtime::{
	RuntimeDebug,
	traits::MaybeDisplay,
};

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Encode, Decode, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct EncryptionResult {
	pub public_key: [u8];
	pub encrypted_secret_key: [u8];
	pub ciphertext: Vec<u8>;
}

sp_api::decl_runtime_apis! {
	pub trait EncryptionApi<Balance> 
		where Balance: Codec + MaybeDisplay,
	{
		fn encrypt() -> Option<EncryptionResult>;

		fn decrypt() -> Option<Bytes>;
	}
}
