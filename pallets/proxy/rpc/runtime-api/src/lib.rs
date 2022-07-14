//! Runtime API definition for iris  pallet.

#![cfg_attr(not(feature = "std"), no_std)]

use sp_core::Bytes;
use sp_std::vec::Vec;

sp_api::decl_runtime_apis! {
	pub trait IrisApi
	{
		fn add_bytes() -> Bytes;
		fn retrieve_bytes(asset_id: u32) -> Bytes;
	}
}
