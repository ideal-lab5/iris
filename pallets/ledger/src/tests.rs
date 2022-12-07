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
use super::*;
use frame_support::{assert_ok};
use crate::mock::{Ledger, Origin, Test, new_test_ext_funded};
use sp_core::Pair;

#[test]
fn ledger_can_lock() {
	let (p, _) = sp_core::sr25519::Pair::generate();
	let pairs = vec![(p.clone().public(), 10)];
	new_test_ext_funded(pairs).execute_with(|| {
		assert_ok!(Ledger::lock_currency(Origin::signed(p.clone().public()), 1));
		let locked_amount = crate::Ledger::<Test>::get(p.public().clone());
		assert_eq!(1, locked_amount);
	});
}

#[test]
fn ledger_can_unlock_and_transfer() {
	let (p, _) = sp_core::sr25519::Pair::generate();
	let (p2, _) = sp_core::sr25519::Pair::generate();

	let pairs = vec![(p.clone().public(), 10)];
	new_test_ext_funded(pairs).execute_with(|| {
		assert_ok!(Ledger::lock_currency(Origin::signed(p.clone().public()), 1));
		
		assert_ok!(
			Ledger::unlock_currency_and_transfer(
				Origin::signed(p.clone().public()),
				p2.clone().public(),
			)
		);
		let locked_amount = crate::Ledger::<Test>::get(p.public().clone());
		assert_eq!(0, locked_amount);
	});
}
