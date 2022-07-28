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

/// Used to track errors as a result of calls to 
#[derive(Eq, Encode, Decode, RuntimeDebug, PartialEq, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum IpfsError {
    EmptyInput,
    IpfsUnavailable,
    IpfsFailedToAddBytes,
    InvalidSignature,
}

/// The result of executing a request to IPFS
#[derive(PartialEq, Eq, Encode, Decode, RuntimeDebug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[cfg_attr(
	feature = "std",
	serde(
		rename_all = "camelCase",
	)
)]
pub struct IpfsResult {
    pub response: Bytes,
    pub error: Option<Vec<IpfsError>>,
}
