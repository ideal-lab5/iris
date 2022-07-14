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
use frame_support::{assert_noop, assert_ok, pallet_prelude::*};
use sp_core::{
	offchain::{testing, OffchainWorkerExt, TransactionPoolExt, OffchainDbExt}
};
use sp_io::TestExternalities;

#[test]
pub fn ipfs_can_call_config_show() {
    let (offchain, state) = testing::TestOffchainExt::new();
	let mut t = TestExternalities::default();
	t.register_extension(OffchainWorkerExt::new(offchain));

	t.execute_with(|| {
		// mcok the post request
		state.write().expect_request(
			testing::PendingRequest {
				method: "POST".into(),
				uri: "https://127.0.0.1:5001/api/v0/config/show".into(),
				body: b"".to_vec(),
				sent: true,
                response: Some(vec![1, 2, 3]),
				..Default::default()
			},
		);

        let res = ipfs::config_show();

		// then check the response
		// let mut headers = response.headers().into_iter();
		// assert_eq!(headers.current(), None);
		// assert_eq!(headers.next(), true);
		// assert_eq!(headers.current(), Some(("Test", "Header")));

		// let body = response.body();
		// assert_eq!(body.clone().collect::<Vec<_>>(), b"".to_vec());
		// assert_eq!(body.error(), &None);
	})
}