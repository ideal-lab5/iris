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
use sp_std::vec::Vec;

use codec::Codec;
use sp_runtime::traits::MaybeDisplay;
use pallet_ipfs_primitives::IpfsResult;

sp_api::decl_runtime_apis! {
	pub trait IpfsApi<Balance> 
		where Balance: Codec + MaybeDisplay,
	{
		fn add_bytes(
			byte_stream: Bytes, 
			asset_id: u32,
			dataspace_id: u32,
			balance: Balance,
			signature: Bytes, 
			signer: Bytes, 
			message: Bytes
		) -> IpfsResult;

		fn retrieve_bytes(asset_id: u32) -> Bytes;
	}
}
