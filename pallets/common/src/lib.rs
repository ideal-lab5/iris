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

#[derive(Eq, Ord, PartialOrd, Encode, Decode, RuntimeDebug, PartialEq, TypeInfo, Clone)]
pub struct IngestionCommand<AccountId, Balance> {
    /// the owner of the data to be ingested (i.e. the caller)
    pub owner: AccountId,
    /// a 'self-reported' estimated size of data to be transferred
    /// the true data size can only be known after querying the OCC within the OCW
    pub estimated_size_gb: u128,
    /// the balance used to create an asset class and pay a proxy node
    pub balance: Balance,
}

// /// Reward points for storage providers of some specific assest id during an era.
// #[derive(PartialEq, Encode, Decode, Default, RuntimeDebug, TypeInfo)]
// pub struct EraRewardPoints<AccountId> {
// 	/// the total number of points
// 	total: RewardPoint,
// 	/// the reward points for individual validators, sum(i.rewardPoint in individual) = total
// 	individual: BTreeMap<AccountId, RewardPoint>,
// }

// /// Information regarding the active era (era in used in session).
// #[derive(Encode, Decode, RuntimeDebug, TypeInfo)]
// pub struct ActiveEraInfo<EraIndex> {
// 	/// Index of era.
// 	pub index: EraIndex,
// 	/// Moment of start expressed as millisecond from `$UNIX_EPOCH`.
// 	///
// 	/// Start can be none if start hasn't been set for the era yet,
// 	/// Start is set on the first on_finalize of the era to guarantee usage of `Time`.
// 	start: Option<u64>,
// }