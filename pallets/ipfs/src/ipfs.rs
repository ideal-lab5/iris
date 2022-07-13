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

/// Update the node's configuration
/// 
/// 
/// * config_item: The ipfs configuration to update. In general, this is a key-value pair.
/// 
pub fn config_update(config_item: IpfsConfigRequest) -> Result<(), http::Error> {
    let endpoint = "http://127.0.0.1:5001/api/v0/config?";
    // endpoint.push_str("arg=");
    // match str::from_utf_8(config_item.key) {
    //     Ok(k) => {
    //         endpoint.push_str(k);
    //     }, 
    //     Err(_e) => {
    //         return Err(http::Error::Unknown);
    //     }
    // }
   
    // "http://127.0.0.1:5001/api/v0/config?arg=<key>&arg=<value>&bool=<value>&json=<value>"
    Ok(())
}

/// Show the node's current configuration
/// 
pub fn config_show() -> Result<http::Response, http::Error> {
    let endpoint = "http://127.0.0.1:5001/api/v0/config/show";
    let res = ipfs_post_request(&endpoint, None).unwrap();
    Ok(res)
}


/// Connect to the given multiaddress
/// 
/// * multiaddress: The multiaddress to connect to
/// 
pub fn connect(multiaddress: &Vec<u8>) -> Result<(), http::Error> {
    match str::from_utf8(multiaddress) {
        Ok(maddr) => {
            let mut endpoint = "http://127.0.0.1:5001/api/v0/swarm/connect?arg=".to_owned();
            endpoint.push_str(maddr);
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
/// * multiaddress: The multiaddress to disconnect from
/// 
pub fn disconnect(multiaddress: &Vec<u8>) -> Result<(), http::Error> {
    match str::from_utf8(multiaddress) {
        Ok(maddr) => {
            let mut endpoint = "http://127.0.0.1:5001/api/v0/swarm/disconnect?arg=".to_owned();
            endpoint.push_str(maddr);
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
/// * ipfs_add_request: The request object containing data to add
/// 
pub fn add(ipfs_add_request: IpfsAddRequest) -> Result<(), http::Error> {
    let mut endpoint = "http://127.0.0.1:5001/api/v0/add";
    Ok(())
}

/// Fetch data from the ipfs swarm and make it available from your node
/// 
/// * cid: The CID to fetch
/// 
pub fn get(cid: &Vec<u8>) -> Result<(), http::Error> {
    match str::from_utf8(cid) {
        Ok(cid_string) => {
            let mut endpoint = "http://127.0.0.1:5001/api/v0/get?arg=".to_owned();
            endpoint.push_str(cid_string);
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
/// cid: The CID to cat
/// 
pub fn cat(cid: &Vec<u8>) -> Result<http::Response, http::Error> {
    match str::from_utf8(cid) {
        Ok(cid_string) => {
            let mut endpoint = "http://127.0.0.1:5001/api/v0/cat?arg=".to_owned();
            endpoint.push_str(cid_string);
            let res = ipfs_post_request(&endpoint, None).ok();
            return Ok(res.unwrap());
        },
        Err(_e) => {
            return Err(http::Error::Unknown);
        }
    }
}

// TODO: could replace http::Error with UTF8Error
fn add_arg(endpoint: &str, arg: &Vec<u8>) -> Result<Vec<u8>, Utf8Error> {
    let mut endpoint = endpoint.to_owned();
    endpoint.push_str("arg=");
    match str::from_utf8(arg) {
        Ok(argument) => {
            endpoint.push_str(argument);
        }, 
        Err(e) => {
            return Err(e);
        }
    }
    Ok(endpoint.as_bytes().to_vec())
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