// Taken from rust 38cd9489f75f4a4387296ee304e2287f7c32c211 libcore.

//! Numeric traits and functions for the built-in numeric types.

// All these modules are technically private and only exposed for coretests:
pub mod flt2dec;
pub mod dec2flt;
pub mod bignum;
pub mod diy_float;
