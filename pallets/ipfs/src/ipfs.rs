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
use serde_json::Value;
use log;

/// A request object to update ipfs configs
#[derive(Encode, Decode, RuntimeDebug, TypeInfo)]
pub struct IpfsConfigRequest {
    /// the key of the config request: the flattened path of the json in the ipfs config to be updated
    /// ex: if you're targeting to update the value of the config item "b" and the json is:
    ///                                  "a": { "b": {...}}
    //      then you would provide the key "a.b"
	pub key: Vec<u8>,
    /// the value to update the config key with
	pub value: Vec<u8>,
	pub boolean: Option<bool>,
	pub json: Option<bool>,
}

/// A request object to add data to ipfs
#[derive(Encode, Decode, RuntimeDebug, TypeInfo)]
pub struct IpfsAddRequest {
    pub bytes: Vec<u8>, 
}

/// IPFS capabilities
#[derive(Clone, PartialEq, Eq, RuntimeDebug)]
pub enum Capabilities {
    Add,
    Cat,
    ConfigShow,
	ConfigUpdate,
	Connect,
    Disconnect, 
    Get,
    Identity,
    Stat,
	Other(&'static str),
}

// TODO: either new param on startup or based on chain spec
/// IPFS capabilities mapped to appropriate RPC endpoints
// impl AsRef<str> for Capabilities {
// 	fn as_ref(&self) -> &str {
// 		match *self {
//             Capabilities::Add => "http://127.0.0.1:5001/api/v0/add",
//             Capabilities::Cat => "http://127.0.0.1:5001/api/v0/cat",
//             Capabilities::ConfigShow => "http://127.0.0.1:5001/api/v0/config/show",
//             Capabilities::ConfigUpdate => "http://127.0.0.1:5001/api/v0/config?",
//             Capabilities::Connect => "http://127.0.0.1:5001/api/v0/swarm/connect?",
//             Capabilities::Disconnect => "http://127.0.0.1:5001/api/v0/swarm/disconnect?",
//             Capabilities::Get => "http://127.0.0.1:5001/api/v0/get?",
//             Capabilities::Identity => "http://127.0.0.1:5001/api/v0/id",
//             Capabilities::Stat => "http://127.0.0.1:5001/api/v0/repo/stat",
// 			Capabilities::Other(m) => m,
// 		}
// 	}
// }

impl AsRef<str> for Capabilities {
	fn as_ref(&self) -> &str {
		match *self {
            Capabilities::Add => "http://host.docker.internal:5001/api/v0/add",
            Capabilities::Cat => "http://host.docker.internal:5001/api/v0/cat",
            Capabilities::ConfigShow => "http://host.docker.internal:5001/api/v0/config/show",
            Capabilities::ConfigUpdate => "http://host.docker.internal:5001/api/v0/config?",
            Capabilities::Connect => "http://host.docker.internal:5001/api/v0/swarm/connect?",
            Capabilities::Disconnect => "http://host.docker.internal:5001/api/v0/swarm/disconnect?",
            Capabilities::Get => "http://host.docker.internal:5001/api/v0/get?",
            Capabilities::Identity => "http://host.docker.internal:5001/api/v0/id",
            Capabilities::Stat => "http://host.docker.internal:5001/api/v0/repo/stat",
			Capabilities::Other(m) => m,
		}
	}
}

/// Get the ipfs node identity
/// 
pub fn identity() -> Result<http::Response, http::Error> {
    let endpoint = Capabilities::Identity.as_ref().to_owned();
    let res = ipfs_post_request(&endpoint, None)?;
    Ok(res)
}

/// Update the node's configuration. For the time being, we omit the optional
/// bool and json arguments
/// 
/// * config_item: The ipfs configuration to update. In general, this is a key-value pair.
/// 
pub fn config_update(config_item: IpfsConfigRequest) -> Result<(), http::Error> {
    let mut endpoint = Capabilities::ConfigUpdate.as_ref().to_owned();
    endpoint = add_arg(endpoint, "arg".as_bytes(), &config_item.key, true)
        .map_err(|_| http::Error::Unknown).unwrap();
    endpoint = add_arg(endpoint, "arg".as_bytes(), &config_item.value, false)
        .map_err(|_| http::Error::Unknown).unwrap();
    ipfs_post_request(&endpoint, None)?;
    Ok(())
}

/// Show the node's current configuration
/// 
pub fn config_show() -> Result<http::Response, http::Error> {
    let endpoint = Capabilities::ConfigShow.as_ref().to_owned();
    let res = ipfs_post_request(&endpoint, None).unwrap();
    Ok(res)
}

/// Get the ipfs repo stats
///
pub fn repo_stat() -> Result<serde_json::Value, http::Error> {
    let endpoint = Capabilities::Stat.as_ref().to_owned();
    let res = ipfs_post_request(&endpoint, None)?;
    let res_u8 = res.body().collect::<Vec<u8>>();
    let body = sp_std::str::from_utf8(&res_u8).map_err(|_| http::Error::Unknown).unwrap();
    let json = parse(body).map_err(|_| http::Error::Unknown).unwrap();
    Ok(json)
}

/// Connect to the given multiaddress
/// 
/// * multiaddress: The multiaddress to connect to
/// 
pub fn connect(multiaddress: &[u8]) -> Result<(), http::Error> {
    let mut endpoint = Capabilities::Connect.as_ref().to_owned();
    endpoint = add_arg(endpoint, "arg".as_bytes(), multiaddress, false)
        .map_err(|_| http::Error::Unknown).unwrap();
    ipfs_post_request(&endpoint, None)?;
    Ok(())
}

/// Disconnect from the given multiaddress
/// 
/// * multiaddress: The multiaddress to disconnect from
/// 
pub fn disconnect(multiaddress: &[u8]) -> Result<(), http::Error> {
    let mut endpoint = Capabilities::Disconnect.as_ref().to_owned();
    endpoint = add_arg(endpoint, "arg".as_bytes(), multiaddress, false)
        .map_err(|_| http::Error::Unknown).unwrap();
    ipfs_post_request(&endpoint, None)?;
    Ok(())
}

/// Add some data to ipfs
/// 
/// For the initial implementation, we will ignore all optional args
/// * ipfs_add_request: The request object containing data to add
/// 
pub fn add(ipfs_add_request: IpfsAddRequest) -> Result<http::Response, http::Error> {
    let endpoint = Capabilities::Add.as_ref();
    // construct body
    // {"path": <file bytes>"}
    let mut req_body = "{ \"path\" : ".to_owned();
    match str::from_utf8(&ipfs_add_request.bytes) {
        Ok(b) => {
            req_body.push_str(b);
        }, 
        Err(e) => {
            log::error!("An error occured while parsing input: {:?}", e);
            return Err(http::Error::Unknown);
        }
    }
    req_body.push_str("}");
    let body: &[u8] = req_body.as_bytes();
    let pending = http::Request::default()
                .add_header("Content-Type", "multipart/form-data")
                .method(http::Method::Post)
                .url(endpoint)
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
pub fn get(cid: &[u8]) -> Result<http::Response, http::Error> {
    let mut endpoint = Capabilities::Get.as_ref().to_owned();
    endpoint = add_arg(endpoint, "arg".as_bytes(), cid, false)
        .map_err(|_| http::Error::Unknown).unwrap();
    let res = ipfs_post_request(&endpoint, None).unwrap();
    Ok(res)
}

/// retrieve data from IPFS and return it
/// 
/// cid: The CID to cat
/// 
pub fn cat(cid: &[u8]) -> Result<http::Response, http::Error> {
    let mut endpoint = Capabilities::Cat.as_ref().to_owned();
    endpoint = add_arg(endpoint, "arg".as_bytes(), cid, false)
        .map_err(|_| http::Error::Unknown).unwrap();
    let res = ipfs_post_request(&endpoint, None);
    Ok(res.unwrap())
}

/// Parse the input string as json
/// 
/// returns Result<serde_json::Value, serde_json::Error>
/// 
pub fn parse(input: &str) -> Result<Value, serde_json::Error> {
    match serde_json::from_str(input) {
        Ok(v) => {
            Ok(v)
        },
        Err(e) => {
            log::error!("An error occured while parsing input: {:?}", e);
            Err(e)
        }
    }
}

/// Append a key-value argument to the endpoint.
/// Returns a Utf8Error if we fail to convert the key or value to utf8
/// 
/// e.g. (endpoint?, k, v, true) => endpoint?k=v&
///      (endpoint?, k, v, false) => endpoint?k=v
/// 
fn add_arg(
    mut endpoint: String,
    key: &[u8],
    value: &[u8],
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
    log::info!("Making POST request to: {:?}", endpoint);
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
    let response = pending.wait()?;
    if response.code != 200 {
        log::error!("Unexpected status code: {}", response.code);
        return Err(http::Error::Unknown);
    }
    Ok(response)
}
