// Taken from rust 9b0214d9c560c49e2836c8491aa21d3dbf9f5554 libcore.

//! Numeric traits and functions for the built-in numeric types.

// All these modules are technically private and only exposed for coretests:
pub mod flt2dec;
pub mod dec2flt;
pub mod bignum;
pub mod diy_float;
