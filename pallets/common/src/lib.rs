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

#[cfg(feature = "std")]
use sp_rpc::number::NumberOrHex;

#[cfg(feature = "std")]
use serde::{
    Deserialize, 
    Serialize,
    de::{Visitor},
};

#[derive(Eq, Ord, PartialOrd, Encode, Decode, RuntimeDebug, PartialEq, TypeInfo, Clone)]
pub struct IngestionCommand<AccountId, AssetId, Balance> {
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
    pub dataspace_id: AssetId,
    /// the balance used to create an asset class and pay a proxy node
    pub balance: Balance,
}

#[derive(Eq, Ord, PartialOrd, Encode, Decode, RuntimeDebug, PartialEq, TypeInfo, Clone, Copy, MaxEncodedLen, Default)]
pub struct AssetId<T: Copy> {
    // #[codec(compact)]
    pub id: T,
}

// // Serialize
// impl<T> Serialize for AssetId<T> {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let mut state = serializer.serialize_struct("AssetId", 1)?;
//         state.serialize_field("id", &self.id)?;
//         state.end()
//     }
// }

// // visitor
// struct AssetIdVisitor;

// impl<'de> Visitor<'de> for AssetIdVisitor {
//     type Value = u32;
//     fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//         formatter.write_str("an asset id greater than 0")
//     }
//     fn visit_u32<E>(self, value: u32) -> Result<Self::Value, E>
//     where
//         E: de::Error
//     {
//         Ok(value)
//     }
// }

// // Deserialize
// impl<'de> Deserialize<'de> for AssetId<u32> {
//     fn deserialize<D>(&self, deserializer: D) -> Result<AssetId<u32>, D:Error> 
//     where 
//         D: Deserializer<'de>,
//     {
//         deserializer.deserialize_u32(AssetIdVisitor)
//     }
// }

// // HasCompact
// impl<T: Copy> CompactAs for AssetId<T> {
//     type As = T;

//     fn encode_as(&self) -> &Self::As {
//         &self.id
//     }

//     fn decode_from(x: Self::As) -> Result<Self, codec::Error> {
//         Ok(AssetId {
//             id: x,
//         })
//     }
// }

// impl<T: Copy> From<Compact<AssetId<T>>> for AssetId<T> {
//     fn from(x: Compact<AssetId<T>>) -> Self {
//         x.0
//     }
// }

// impl From<u32> for AssetId<u32> {
//     fn from(u: u32) -> AssetId<u32> {
//         AssetId { id: u }
//     }
// }