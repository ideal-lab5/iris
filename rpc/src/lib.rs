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
	core::{async_trait, RpcResult},
	proc_macros::rpc,
	types::error::{CallError, ErrorObject},
};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_core::{
	Bytes,
};
use sp_runtime::{
	generic::BlockId,
	traits::{Block as BlockT, MaybeDisplay},
};
use sp_rpc::number::NumberOrHex;
use std::sync::Arc;
use codec::Codec;

pub use encryption_rpc_runtime_api::EncryptionApi as EncryptionRuntimeApi;

#[rpc(client, server)]
pub trait EncryptionApi<BlockHash, Balance> {

	/// Encrypts the ciphertext using the signer's public keys
	/// and delegates reencryption rights to the proxy
	/// 
	/// * `plaintext`: The plaintext to be encrypted
	/// * `signature`: The signature created to sign the message
	/// * `message`: A signed message
	/// * `signer`: The address of the node who signed the message
	/// * `proxy`: The proxy to delegate reencryption rights to
	///  
	#[method(name = "iris_encrypt")]
	fn encrypt(
		&self,
		plaintext: Bytes,
        signature: Bytes,
        signer: Bytes,
        message: Bytes,
		proxy: Bytes,
		at: Option<BlockHash>,
	) -> RpcResult<Bytes>;

	/// Decrypts ciphertext encrypted with Iris that the signer has access to.
	/// 
	/// * `ciphertext`: The ciphertext to be decrypted
	/// * `signature`: The signature created to sign the message
	/// * `message`: A signed message
	/// * `signer`: The address of the node who signed the mess
	/// * `asset_id`: The asset id associated with the data asset
	/// * `secret_key`: A secret key whose corresponding public key was passed to the rule executor
	/// 
	#[method(name = "iris_decrypt")]
	fn decrypt(
		&self,
		ciphertext: Bytes,
		signature: Bytes,
		signer: Bytes,
		message: Bytes,
		asset_id: u32,
		secret_key: Bytes,
		at: Option<BlockHash>,
	) -> RpcResult<Option<Bytes>>;
}

/// A struct that implements EncryptionRpc
pub struct Encryption<C, P> {
	client: Arc<C>,
	_marker: std::marker::PhantomData<P>,
}

impl<C, P> Encryption<C, P> {
	/// create new 'Encrypt' instance with the given reference	to the client
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
impl<C, Block, Balance> 
	EncryptionApiServer<<Block as BlockT>::Hash, Balance> for Encryption<C, Block>
where 
	Block: BlockT,
	C: ProvideRuntimeApi<Block> + HeaderBackend<Block> + Send + Sync + 'static,
	C::Api: EncryptionRuntimeApi<Block, Balance>,
	Balance: Codec + MaybeDisplay + Copy + TryInto<NumberOrHex> + Send + Sync + 'static,
{

	fn encrypt(
		&self,
		plaintext: Bytes,
        signature: Bytes,
        signer: Bytes,
        message: Bytes,
		proxy: Bytes,
		at: Option<<Block as BlockT>::Hash>
	) -> RpcResult<Bytes> {
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or_else(||
			self.client.info().best_hash
		));
		api.encrypt(&at, plaintext, signature, signer, message, proxy)
			.map_err(|e| {
				CallError::Custom(ErrorObject::owned(
					Error::RuntimeError.into(),
					"Unable to add bytes.",
					Some(e.to_string())
				)
			).into()
		})
	}

	fn decrypt(
		&self,
		ciphertext: Bytes,
		signature: Bytes,
		signer: Bytes,
		message: Bytes,
		asset_id: u32,
		secret_key: Bytes,
		at: Option<<Block as BlockT>::Hash>
	) -> RpcResult<Option<Bytes>> {
		let api = self.client.runtime_api();
		let at = BlockId::hash(at.unwrap_or_else(||
			self.client.info().best_hash
		));
		api.decrypt(&at, ciphertext, signature, signer, message, asset_id, secret_key).map_err(|e| {
			CallError::Custom(ErrorObject::owned(
				Error::RuntimeError.into(),
				"Unable to retrieve bytes.",
				Some(e.to_string())
			)).into()
		})
	}
}