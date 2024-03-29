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

use sp_core::Bytes;

use codec::Codec;
use sp_runtime::{
	traits::MaybeDisplay,
};

sp_api::decl_runtime_apis! {
	pub trait EncryptionApi<Balance> 
		where Balance: Codec + MaybeDisplay,
	{
		fn encrypt(
			plaintext: Bytes,
			signature: Bytes,
			signer: Bytes,
			message: Bytes,
			proxy: Bytes,
		) -> Bytes;

		fn decrypt(
			ciphertext: Bytes,
			signature: Bytes,
			signer: Bytes,
			message: Bytes,
			asset_id: u32,
			secret_key: Bytes,
		) -> Option<Bytes>;

	}
}
