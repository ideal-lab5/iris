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

use jsonrpsee::{
	core::{async_trait, Error as JsonRpseeError, RpcResult},
	proc_macros::rpc,
	types::error::{CallError, ErrorCode, ErrorObject},
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::{
	Bytes,
	sr25519::{Signature, Public}
};
use sp_runtime::{
	generic::BlockId,
	traits::{Block as BlockT},
};
use std::sync::Arc;
use codec::{Codec, Decode, Encode};
use sp_std::vec::Vec;

pub use pallet_ipfs_rpc_runtime_api::IpfsApi as IpfsRuntimeApi;

#[rpc(client, server)]
pub trait IpfsApi<BlockHash> {

	#[method(name = "ipfs_addBytes")]
	fn add_bytes(
		&self,
		byte_stream: Bytes,
		asset_id: u32,
		signature: Bytes,
		signer: Bytes,
		message: Bytes,
		at: Option<BlockHash>,
	) -> RpcResult<Bytes>;

	#[method(name = "ipfs_retrieveBytes")]
	fn retrieve_bytes(
		&self,
		asset_id: u32,
		at: Option<BlockHash>,
	) -> RpcResult<Bytes>;
}

/// A struct that implements IpfsRpc
pub struct Ipfs<C, P> {
	client: Arc<C>,
	_marker: std::marker::PhantomData<P>,
}

impl<C, P> Ipfs<C, P> {
	/// create new 'Ipfs' instance with the given reference	to the client
	pub fn new(client: Arc<C>) -> Self {
		Self { client, _marker: Default::default() }
	}
}

/// Errors encountered by the RPC
pub enum Error {
	/// the call to runtime failed
	RuntimeError,
}

impl From<Error> for i32 {
	fn from(e: Error) -> i32 {
		match e {
			Error::RuntimeError => 1,
		}
	}
}

#[async_trait]
impl<C, Block> 
	IpfsApiServer<<Block as BlockT>::Hash>
	for Ipfs<C, Block>
where 
	Block: BlockT,
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: IpfsRuntimeApi<Block>,
{

	fn add_bytes(
		&self,
		byte_stream: Bytes,
		asset_id: u32,
		signature: Bytes,
		signer: Bytes,
		message: Bytes,
		at: Option<<Block as BlockT>::Hash>
	) -> RpcResult<Bytes> {
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or_else(||
			self.client.info().best_hash
		));
		api.retrieve_bytes(&at, asset_id).map_err(|e| {
			CallError::Custom(ErrorObject::owned(
				Error::RuntimeError.into(),
				"Unable to add bytes.",
				Some(e.to_string())
			)).into()
		})
	}

	fn retrieve_bytes(
		&self,
		asset_id: u32,
		at: Option<<Block as BlockT>::Hash>
	) -> RpcResult<Bytes> {
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or_else(||
			self.client.info().best_hash
		));
		api.retrieve_bytes(&at, asset_id).map_err(|e| {
			CallError::Custom(ErrorObject::owned(
				Error::RuntimeError.into(),
				"Unable to retrieve bytes.",
				Some(e.to_string())
			)).into()
		})
	}
}