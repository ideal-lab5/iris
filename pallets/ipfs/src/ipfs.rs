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
//! 
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
// use core::alloc::str::UTF8Error;

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

/// Update the node's configuration. For the time being, we omit the optional
/// bool and json arguments
/// 
/// http://127.0.0.1:5001/api/v0/config?arg=<key>&arg=<value>&bool=<value>&json=<value>
/// 
/// * config_item: The ipfs configuration to update. In general, this is a key-value pair.
/// 
pub fn config_update(config_item: IpfsConfigRequest) -> Result<(), http::Error> {
    let mut endpoint = "http://127.0.0.1:5001/api/v0/config?".to_string();
    endpoint = add_arg(endpoint, &"key".as_bytes().to_vec(), &config_item.key, true)
        .map_err(|_| http::Error::Unknown).ok().unwrap();
    endpoint = add_arg(endpoint, &"value".as_bytes().to_vec(), &config_item.value, false)
        .map_err(|_| http::Error::Unknown).ok().unwrap();
    ipfs_post_request(&endpoint, None)?;
    Ok(())
}

/// Show the node's current configuration
/// 
/// http://127.0.0.1:5001/api/v0/config/show
/// 
pub fn config_show() -> Result<http::Response, http::Error> {
    let endpoint = "http://127.0.0.1:5001/api/v0/config/show";
    let res = ipfs_post_request(&endpoint, None).unwrap();
    Ok(res)
}


/// Connect to the given multiaddress
/// 
/// http://127.0.0.1:5001/api/v0/swarm/connect?arg={maddr}
/// 
/// * multiaddress: The multiaddress to connect to
/// 
pub fn connect(multiaddress: &Vec<u8>) -> Result<(), http::Error> {
    match str::from_utf8(multiaddress) {
        Ok(maddr) => {
            let mut endpoint = "http://127.0.0.1:5001/api/v0/swarm/connect?";
            endpoint = add_arg(endpoint, &"arg".as_bytes().to_vec(), &maddr, false)
                .map_err(|_| http::Error::Unknown).ok().unwrap();
            ipfs_post_request(&endpoint, None).unwrap();
            return Ok(());
        },
        Err(_e) => {
            return Err(http::Error::Unknown);
        }
    }
}

/// Disconeect from the given multiaddress
/// 
/// http://127.0.0.1:5001/api/v0/swarm/disconnect?arg={maddr}
/// 
/// * multiaddress: The multiaddress to disconnect from
/// 
pub fn disconnect(multiaddress: &Vec<u8>) -> Result<(), http::Error> {
    match str::from_utf8(multiaddress) {
        Ok(maddr) => {
            let mut endpoint = "http://127.0.0.1:5001/api/v0/swarm/disconnect?";
            endpoint = add_arg(endpoint, &"arg".as_bytes().to_vec(), &maddr, false)
                .map_err(|_| http::Error::Unknown).ok().unwrap();
            ipfs_post_request(&endpoint, None).unwrap();
            return Ok(());
        },
        Err(_e) => {
            return Err(http::Error::Unknown);
        }
    }
}

/// Add some data to ipfs
/// 
/// http://127.0.0.1:5001/api/v0/add
/// 
/// TODO: not yet implemented
/// 
/// * ipfs_add_request: The request object containing data to add
/// 
pub fn add(ipfs_add_request: IpfsAddRequest) -> Result<(), http::Error> {
    let mut endpoint = "http://127.0.0.1:5001/api/v0/add";
    Ok(())
}

/// Fetch data from the ipfs swarm and make it available from your node
/// 
/// http://127.0.0.1:5001/api/v0/get?
/// 
/// * cid: The CID to fetch
/// 
pub fn get(cid: &Vec<u8>) -> Result<(), http::Error> {
    match str::from_utf8(cid) {
        Ok(cid_string) => {
            let mut endpoint = "http://127.0.0.1:5001/api/v0/get?";
            endpoint = add_arg(endpoint, &"arg".as_bytes().to_vec(), &cid_string, false)
                .map_err(|_| http::Error::Unknown).ok().unwrap();
            ipfs_post_request(&endpoint, None).unwrap();
            return Ok(());
        },
        Err(_e) => {
            return Err(http::Error::Unknown);
        }
    }
}

/// retrieve data from IPFS and return it
/// 
/// http://127.0.0.1:5001/api/v0/cat?
/// 
/// cid: The CID to cat
/// 
pub fn cat(cid: &Vec<u8>) -> Result<http::Response, http::Error> {
    match str::from_utf8(cid) {
        Ok(cid_string) => {
            let mut endpoint = "http://127.0.0.1:5001/api/v0/cat?";
            endpoint = add_arg(endpoint, &"arg".as_bytes().to_vec(), &cid_string, false)
                .map_err(|_| http::Error::Unknown).ok().unwrap();
            let res = ipfs_post_request(&endpoint, None).ok();
            return Ok(res.unwrap());
        },
        Err(_e) => {
            return Err(http::Error::Unknown);
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
    endpoint: std::string::String,
    key: &Vec<u8>,
    value: &Vec<u8>,
    append_and: bool,
) -> Result<std::string::String, Utf8Error> {
    let mut endpoint = endpoint.to_owned();
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

// #![cfg(test)]

use super::*;
use frame_support::{assert_noop, assert_ok, pallet_prelude::*};
use sp_core::{
	offchain::{testing, OffchainWorkerExt, TransactionPoolExt, OffchainDbExt}
};


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