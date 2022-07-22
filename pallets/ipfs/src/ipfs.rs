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

//!
//! functions that make HTTP calls to various IPFS endpoints
//!
use codec::{Encode, Decode};
use scale_info::TypeInfo;
use sp_std::{
    str,
    str::Utf8Error,
    vec::Vec,
    prelude::*,
};
use sp_runtime::{
    offchain::http,
    RuntimeDebug,
};
use scale_info::prelude::string::String;

/// A request object to update ipfs configs
#[derive(Encode, Decode, RuntimeDebug, TypeInfo)]
pub struct IpfsConfigRequest {
	key: Vec<u8>,
	value: Vec<u8>,
	boolean: Option<bool>,
	json: Option<bool>,
}

/// A request object to add data to ipfs
#[derive(Encode, Decode, RuntimeDebug, TypeInfo)]
pub struct IpfsAddRequest {
    bytes: Vec<u8>, 
}

/// IPFS capabilities
#[derive(Clone, PartialEq, Eq, RuntimeDebug)]
pub enum Endpoint {
	ConfigUpdate,
	ConfigShow,
	Connect,
    Disconnect, 
    Add,
    Get, 
    Cat,
	Other(&'static str),
}

/// IPFS capabilities mapped to appropriate RPC endpoints
impl AsRef<str> for Endpoint {
	fn as_ref(&self) -> &str {
		match *self {
            Endpoint::ConfigUpdate => "https://127.0.0.1:5001/api/v0/config?",
            Endpoint::ConfigShow => "https://127.0.0.1:5001/api/v0/config/show",
            Endpoint::Connect => "https://127.0.0.1:5001/api/v0/swarm/connect?",
            Endpoint::Disconnect => "https://127.0.0.1:5001/api/v0/swarm/disconnect?",
            Endpoint::Add => "https://127.0.0.1:5001/api/v0/add",
            Endpoint::Get => "https://127.0.0.1:5001/api/v0/get",
            Endpoint::Cat => "https://127.0.0.1:5001/api/v0/cat",
			Endpoint::Other(m) => m,
		}
	}
}

/// Update the node's configuration. For the time being, we omit the optional
/// bool and json arguments
/// 
/// * config_item: The ipfs configuration to update. In general, this is a key-value pair.
/// 
pub fn config_update(config_item: IpfsConfigRequest) -> Result<(), http::Error> {
    let mut endpoint = Endpoint::ConfigUpdate.as_ref().to_owned();
    endpoint = add_arg(endpoint, &"key".as_bytes().to_vec(), &config_item.key, true)
        .map_err(|_| http::Error::Unknown).ok().unwrap();
    endpoint = add_arg(endpoint, &"value".as_bytes().to_vec(), &config_item.value, false)
        .map_err(|_| http::Error::Unknown).ok().unwrap();
    ipfs_post_request(&endpoint, None)?;
    Ok(())
}

/// Show the node's current configuration
/// 
pub fn config_show() -> Result<http::Response, http::Error> {
    let endpoint = Endpoint::ConfigShow.as_ref().to_owned();
    let res = ipfs_post_request(&endpoint, None).unwrap();
    Ok(res)
}


/// Connect to the given multiaddress
/// 
/// * multiaddress: The multiaddress to connect to
/// 
pub fn connect(multiaddress: &Vec<u8>) -> Result<(), http::Error> {
    let mut endpoint = Endpoint::Connect.as_ref().to_owned();
    endpoint = add_arg(endpoint, &"arg".as_bytes().to_vec(), multiaddress, false)
        .map_err(|_| http::Error::Unknown).ok().unwrap();
    ipfs_post_request(&endpoint, None)?;
    Ok(())
}

/// Disconnect from the given multiaddress
/// 
/// * multiaddress: The multiaddress to disconnect from
/// 
pub fn disconnect(multiaddress: &Vec<u8>) -> Result<(), http::Error> {
    let mut endpoint = Endpoint::Disconnect.as_ref().to_owned();
    endpoint = add_arg(endpoint, &"arg".as_bytes().to_vec(), multiaddress, false)
        .map_err(|_| http::Error::Unknown).ok().unwrap();
    ipfs_post_request(&endpoint, None)?;
    Ok(())
}

/// Add some data to ipfs
/// 
/// For the initial implementation, we will ignore all optional args
/// * ipfs_add_request: The request object containing data to add
/// 
pub fn add(ipfs_add_request: IpfsAddRequest) -> Result<http::Response, http::Error> {
    let mut endpoint = Endpoint::Add.as_ref();
    // construct body
    // {"path": <file bytes>"}
    let mut req_body = "{ \"path\" : ".to_owned();
    match str::from_utf8(&ipfs_add_request.bytes) {
        Ok(b) => {
            req_body.push_str(b);
        }, 
        Err(e) => {
            return Err(http::Error::Unknown);
        }
    }
    req_body.push_str(&"}".to_owned());
    let body: &[u8] = req_body.as_bytes();
    let pending = http::Request::default()
                .add_header("Content-Type", "multipart/form-data")
                .method(http::Method::Post)
                .url(&endpoint)
                .body(vec![body])
                .send()
                .unwrap();
    let response = pending.wait().unwrap();
    if response.code != 200 {
        log::warn!("Unexpected status code: {}", response.code);
        return Err(http::Error::Unknown);
    }
    Ok(response)
}

/// Fetch data from the ipfs swarm and make it available from your node
/// 
/// * cid: The CID to fetch.
/// 
/// 
pub fn get(cid: &Vec<u8>) -> Result<(), http::Error> {
    let mut endpoint = Endpoint::Get.as_ref().to_owned();
    endpoint = add_arg(endpoint, &"arg".as_bytes().to_vec(), cid, false)
        .map_err(|_| http::Error::Unknown).ok().unwrap();
    ipfs_post_request(&endpoint, None).unwrap();
    Ok(())
}

/// retrieve data from IPFS and return it
/// 
/// cid: The CID to cat
/// 
pub fn cat(cid: &Vec<u8>) -> Result<http::Response, http::Error> {
    let mut endpoint = Endpoint::Cat.as_ref().to_owned();
    endpoint = add_arg(endpoint, &"arg".as_bytes().to_vec(), cid, false)
        .map_err(|_| http::Error::Unknown).ok().unwrap();
    let res = ipfs_post_request(&endpoint, None).ok();
    Ok(res.unwrap())
}

/// Append a key-value argument to the endpoint.
/// Returns a Utf8Error if we fail to convert the key or value to utf8
/// 
/// e.g. (endpoint?, k, v, true) => endpoint?k=v&
///      (endpoint?, k, v, false) => endpoint?k=v
/// 
fn add_arg(
    mut endpoint: String,
    key: &Vec<u8>,
    value: &Vec<u8>,
    append_and: bool,
) -> Result<String, Utf8Error> {
    match str::from_utf8(key) {
        Ok(k) => {
            match str::from_utf8(value) {
                Ok(v) => {
                    endpoint.push_str(k);
                    endpoint.push_str("=");
                    endpoint.push_str(v);
                    if append_and {
                        endpoint.push_str("&");
                    }
                },
                Err(e) => return Err(e),
            }
        }, 
        Err(e) => return Err(e)
    }
    Ok(endpoint)
}

/// Make an http post request to IPFS
/// 
/// * `endpoint`: The IPFS endpoint to invoke
/// 
fn ipfs_post_request(endpoint: &str, body: Option<Vec<&[u8]>>) -> Result<http::Response, http::Error> {
    let body = match body {
        Some(v) => v,
        None => Vec::new(),
    };
    let pending = http::Request::default()
                .method(http::Method::Post)
                .url(endpoint)
                .body(body)
                .send()
                .unwrap();
    let response = pending.wait().unwrap();
    if response.code != 200 {
        log::warn!("Unexpected status code: {}", response.code);
        return Err(http::Error::Unknown);
    }
    Ok(response)
}

mod tests {

    use super::*;
    use frame_support::{assert_noop, assert_ok, pallet_prelude::*};

    #[test]
    pub fn ipfs_can_add_arg() {
        let input = "https://localhost.com?".to_string();
        let k_1 = "amphibian".as_bytes().to_vec();
        let v_1 = "salamander".as_bytes().to_vec();
    
        let k_2 = "reptile".as_bytes().to_vec();
        let v_2 = "alligator".as_bytes().to_vec();
    
        let expected_output = "https://localhost.com?amphibian=salamander&reptile=alligator";
        let next_input = add_arg(input, &k_1, &v_1, true).unwrap();
        let actual_output = add_arg(next_input, &k_2, &v_2, false).unwrap();
        assert_eq!(expected_output, actual_output);
    }
}