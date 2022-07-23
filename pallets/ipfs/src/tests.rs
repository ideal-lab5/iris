// // This file is part of Iris.
// //
// // Copyright (C) 2022 Ideal Labs.
// //
// // This program is free software: you can redistribute it and/or modify
// // it under the terms of the GNU General Public License as published by
// // the Free Software Foundation, either version 3 of the License, or
// // (at your option) any later version.
// //
// // This program is distributed in the hope that it will be useful,
// // but WITHOUT ANY WARRANTY; without even the implied warranty of
// // MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// // GNU General Public License for more details.
// //
// // You should have received a copy of the GNU General Public License
// // along with this program. If not, see <https://www.gnu.org/licenses/>.

#![cfg(test)]

use super::*;
// use crate::mock::{
// 	authorities, new_test_ext, new_test_ext_funded, 
// 	Origin, Session, Test, Authorities, DataAssets, Assets,
// };
use frame_support::{assert_noop, assert_ok, pallet_prelude::*};
use sp_runtime::testing::UintAuthorityId;
use sp_core::Pair;
use sp_core::{
	offchain::{testing, OffchainWorkerExt, TransactionPoolExt, OffchainDbExt}
};
use sp_keystore::{testing::KeyStore, KeystoreExt, SyncCryptoStore};
use std::sync::Arc;
use sp_io::TestExternalities;

// #[test]
// pub fn ipfs_ocw_can_update_configs() {

// }