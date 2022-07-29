#![no_std]
#![cfg_attr(not(feature = "std"), no_std)]

/// a placeholder interface to mock interactions with the offchain client

use sp_std::vec::Vec;

pub fn write(data: Vec<u8>) {

}

pub fn read(id: Vec<u8>) -> Vec<u8> {
    Vec::new()
}

pub fn authorize() {

}