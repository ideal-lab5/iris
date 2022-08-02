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

use codec::{Decode, Encode};
use sp_core::Bytes;
use sp_runtime::RuntimeDebug;
use sp_std::vec::Vec;
use scale_info::TypeInfo;

#[cfg(feature = "std")]
use sp_rpc::number::NumberOrHex;

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

#[derive(Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
pub struct IngestionCommand<AccountId, AssetId, OccId, Balance> {
    pub owner: AccountId,
    /// the desired asset id
    pub asset_id: AssetId,
    /// the dataspace id to associate the asset with
    pub dataspace_id: AssetId,
    /// the id of the data within the offchain client
    pub occ_id: OccId,
    /// a 'self-reported' estimated size of data to be transferred
    /// the true data size can only be known after querying the OCC within the OCW
    pub estimated_size_gb: u128,
    /// the balance used to create an asset class and pay a proxy node
    pub balance: Balance,
}