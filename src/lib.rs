// Copyright 2019 Eduardo Sánchez Muñoz
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! This crate provides auxiliary functions used to encode and decode
//! S-expression atom values.
//!
//! # Minimum Rust version
//!
//! The minimum Rust version required by this crate is 1.55.

#![deny(
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unreachable_pub,
    unused_must_use,
    unused_qualifications
)]
#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use core::convert::TryFrom as _;
use core::fmt::Write as _;

#[cfg(test)]
mod tests;

// Make this crate only compile on Rust >=1.55
// because previous versions have buggy float parsing.
// Open range patterns (e.g., `0..`) have been stabilized
// in Rust 1.55, so this will fail to compile on previous
// versions.
const _: bool = matches!(0, 0..);

// Encode
/// Encodes a boolean value
///
///
/// Returns `"true"` if `value` is `true`, otherwise returns `"false"`.
pub fn encode_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

/// Encodes a signed 8-bit integer
#[inline]
pub fn encode_i8(value: i8) -> String {
    value.to_string()
}

/// Encodes a signed 16-bit integer
#[inline]
pub fn encode_i16(value: i16) -> String {
    value.to_string()
}

/// Encodes a signed 32-bit integer
#[inline]
pub fn encode_i32(value: i32) -> String {
    value.to_string()
}

/// Encodes a signed 64-bit integer
#[inline]
pub fn encode_i64(value: i64) -> String {
    value.to_string()
}

/// Encodes a signed 128-bit integer
#[inline]
pub fn encode_i128(value: i128) -> String {
    value.to_string()
}

/// Encodes an unsigned 8-bit integer
#[inline]
pub fn encode_u8(value: u8) -> String {
    value.to_string()
}

/// Encodes an unsigned 16-bit integer
#[inline]
pub fn encode_u16(value: u16) -> String {
    value.to_string()
}

/// Encodes an unsigned 32-bit integer
#[inline]
pub fn encode_u32(value: u32) -> String {
    value.to_string()
}

/// Encodes an unsigned 64-bit integer
#[inline]
pub fn encode_u64(value: u64) -> String {
    value.to_string()
}

/// Encodes an unsigned 128-bit integer
#[inline]
pub fn encode_u128(value: u128) -> String {
    value.to_string()
}

fn reformat_float(s: String) -> String {
    if s == "NaN" || s == "inf" || s == "-inf" {
        return s;
    }

    const ZEROS_THRESHOLD: u32 = 9;

    let mut result = String::new();
    let s = if let Some(remaining) = s.strip_prefix('-') {
        result.push('-');
        remaining
    } else {
        s.as_str()
    };

    if let Some(mut remaining) = s.strip_prefix("0.") {
        let mut exp_abs: u32 = 1;
        while let Some(new_remaining) = remaining.strip_prefix('0') {
            remaining = new_remaining;
            exp_abs += 1;
        }
        if exp_abs > ZEROS_THRESHOLD {
            result.push_str(&remaining[..1]);
            if remaining.len() > 1 {
                result.push('.');
                result.push_str(&remaining[1..]);
            } else {
                result.push_str(".0");
            }
            result.push_str("e-");
            write!(result, "{}", exp_abs).unwrap();
        } else {
            result.push_str(s);
        }
    } else {
        let s = s.strip_suffix(".0").unwrap_or(s);
        if s.contains('.') {
            result.push_str(s);
        } else {
            let mut remaining = s;
            let mut num_zeros: u32 = 0;
            while let Some(new_remaining) = remaining.strip_suffix('0') {
                remaining = new_remaining;
                num_zeros += 1;
            }
            if num_zeros > ZEROS_THRESHOLD {
                result.push_str(&remaining[..1]);
                if remaining.len() > 1 {
                    result.push('.');
                    result.push_str(&remaining[1..]);
                } else {
                    result.push_str(".0");
                }
                result.push('e');
                write!(result, "{}", num_zeros + (remaining.len() as u32 - 1)).unwrap();
            } else {
                result.push_str(s);
                result.push_str(".0");
            }
        }
    }

    result
}

/// Encodes a 32-bit floating point number
#[inline]
pub fn encode_f32(value: f32) -> String {
    reformat_float(value.to_string())
}

/// Encodes a 64-bit floating point number
#[inline]
pub fn encode_f64(value: f64) -> String {
    reformat_float(value.to_string())
}

#[inline]
fn nibble_to_hex(nibble: u8) -> char {
    if nibble < 10 {
        char::from(b'0' + nibble)
    } else {
        char::from(b'a' + nibble - 10)
    }
}

pub fn encode_byte_string(string: &[u8]) -> String {
    let mut result = String::with_capacity(string.len() + 2);
    result.push('"');
    for &chr in string {
        #[allow(clippy::match_overlapping_arm)]
        match chr {
            b'\0' => result.push_str("\\0"),
            b'\t' => result.push_str("\\t"),
            b'\n' => result.push_str("\\n"),
            b'\r' => result.push_str("\\r"),
            b'"' => result.push_str("\\\""),
            b'\\' => result.push_str("\\\\"),
            0x20..=0x7E => result.push(char::from(chr)),
            _ => {
                result.push_str("\\x");
                result.push(nibble_to_hex(chr >> 4));
                result.push(nibble_to_hex(chr & 0xF));
            }
        }
    }
    result.push('"');
    result
}

pub fn encode_ascii_string(string: &str) -> String {
    let mut result = String::with_capacity(string.len() + 2);
    result.push('"');
    for &chr in string.as_bytes() {
        #[allow(clippy::match_overlapping_arm)]
        match chr {
            b'\0' => result.push_str("\\0"),
            b'\t' => result.push_str("\\t"),
            b'\n' => result.push_str("\\n"),
            b'\r' => result.push_str("\\r"),
            b'"' => result.push_str("\\\""),
            b'\\' => result.push_str("\\\\"),
            0x20..=0x7E => result.push(char::from(chr)),
            _ => {
                assert!(chr <= 0x7F, "Invalid ASCII character");
                result.push_str("\\x");
                result.push(nibble_to_hex(chr >> 4));
                result.push(nibble_to_hex(chr & 0xF));
            }
        }
    }
    result.push('"');
    result
}

pub fn encode_utf8_string(string: &str) -> String {
    let mut result = String::with_capacity(string.len() + 2);
    result.push('"');
    for chr in string.chars() {
        match chr {
            '\0' => result.push_str("\\0"),
            '\t' => result.push_str("\\t"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\x20'..='\x7E' => result.push(chr),
            _ => {
                result.push_str("\\u{");
                let code_beginning = result.len();
                let mut remaining_digits = u32::from(chr);
                loop {
                    result.insert(
                        code_beginning,
                        nibble_to_hex((remaining_digits & 0xF) as u8),
                    );
                    remaining_digits >>= 4;
                    if remaining_digits == 0 {
                        break;
                    }
                }
                result.push('}');
            }
        }
    }
    result.push('"');
    result
}

// Decode
/// Decodes a boolean value
///
/// Returns `Some(true)` if `atom` is `"true"`, `Some(false)`
/// if `atom` is `"false"`, or `None` otherwise.
#[inline]
pub fn decode_bool(atom: &str) -> Option<bool> {
    match atom {
        "false" => Some(false),
        "true" => Some(true),
        _ => None,
    }
}

/// Decodes a signed 8-bit integer
#[inline]
pub fn decode_i8(atom: &str) -> Option<i8> {
    atom.parse().ok()
}

/// Decodes a signed 16-bit integer
#[inline]
pub fn decode_i16(atom: &str) -> Option<i16> {
    atom.parse().ok()
}

/// Decodes a signed 32-bit integer
#[inline]
pub fn decode_i32(atom: &str) -> Option<i32> {
    atom.parse().ok()
}

/// Decodes a signed 64-bit integer
#[inline]
pub fn decode_i64(atom: &str) -> Option<i64> {
    atom.parse().ok()
}

/// Decodes a signed 128-bit integer
#[inline]
pub fn decode_i128(atom: &str) -> Option<i128> {
    atom.parse().ok()
}

/// Decodes an unsigned 8-bit integer
#[inline]
pub fn decode_u8(atom: &str) -> Option<u8> {
    atom.parse().ok()
}

/// Decodes an unsigned 16-bit integer
#[inline]
pub fn decode_u16(atom: &str) -> Option<u16> {
    atom.parse().ok()
}

/// Decodes an unsigned 32-bit integer
#[inline]
pub fn decode_u32(atom: &str) -> Option<u32> {
    atom.parse().ok()
}

/// Decodes an unsigned 64-bit integer
#[inline]
pub fn decode_u64(atom: &str) -> Option<u64> {
    atom.parse().ok()
}

/// Decodes an unsigned 128-bit integer
#[inline]
pub fn decode_u128(atom: &str) -> Option<u128> {
    atom.parse().ok()
}

/// Decodes a 32-bit floating point number
#[inline]
pub fn decode_f32(atom: &str) -> Option<f32> {
    if atom == "+NaN" || atom == "-NaN" {
        None
    } else {
        atom.parse().ok()
    }
}

/// Decodes a 64-bit floating point number
#[inline]
pub fn decode_f64(atom: &str) -> Option<f64> {
    if atom == "+NaN" || atom == "-NaN" {
        None
    } else {
        atom.parse().ok()
    }
}

#[inline]
fn hex_digit_byte_to_u8(chr: u8) -> Option<u8> {
    match chr {
        b'0'..=b'9' => Some(chr - b'0'),
        b'A'..=b'F' => Some(chr - b'A' + 10),
        b'a'..=b'f' => Some(chr - b'a' + 10),
        _ => None,
    }
}

#[inline]
fn hex_digit_char_to_u8(chr: char) -> Option<u8> {
    match chr {
        '0'..='9' => Some(chr as u8 - b'0'),
        'A'..='F' => Some(chr as u8 - b'A' + 10),
        'a'..='f' => Some(chr as u8 - b'a' + 10),
        _ => None,
    }
}

pub fn decode_byte_string(atom: &str) -> Option<Vec<u8>> {
    let mut iter = atom.bytes();
    if iter.next() != Some(b'"') {
        return None;
    }

    let mut string = Vec::new();
    loop {
        match iter.next() {
            None => return None,
            Some(b'"') => {
                if iter.next().is_some() {
                    return None;
                }
                break;
            }
            Some(b'\\') => match iter.next() {
                Some(b'0') => string.push(b'\0'),
                Some(b't') => string.push(b'\t'),
                Some(b'n') => string.push(b'\n'),
                Some(b'r') => string.push(b'\r'),
                Some(b'"') => string.push(b'\"'),
                Some(b'\\') => string.push(b'\\'),
                Some(b'x') => {
                    let hex1 = hex_digit_byte_to_u8(iter.next()?)?;
                    let hex2 = hex_digit_byte_to_u8(iter.next()?)?;
                    string.push((hex1 << 4) | hex2);
                }
                Some(_) | None => return None,
            },
            Some(byte) => string.push(byte),
        }
    }

    Some(string)
}

pub fn decode_ascii_string(atom: &str) -> Option<String> {
    let mut iter = atom.bytes();
    if iter.next() != Some(b'"') {
        return None;
    }

    let mut string = String::new();
    loop {
        match iter.next() {
            None => return None,
            Some(b'"') => {
                if iter.next().is_some() {
                    return None;
                }
                break;
            }
            Some(b'\\') => match iter.next() {
                Some(b'0') => string.push('\0'),
                Some(b't') => string.push('\t'),
                Some(b'n') => string.push('\n'),
                Some(b'r') => string.push('\r'),
                Some(b'"') => string.push('\"'),
                Some(b'\\') => string.push('\\'),
                Some(b'x') => {
                    let hex1 = hex_digit_byte_to_u8(iter.next()?)?;
                    let hex2 = hex_digit_byte_to_u8(iter.next()?)?;
                    let chr = (hex1 << 4) | hex2;
                    if chr > 0x7F {
                        return None;
                    }
                    string.push(char::from(chr));
                }
                Some(_) | None => return None,
            },
            Some(byte @ b'\x00'..=b'\x7F') => string.push(char::from(byte)),
            Some(_) => return None,
        }
    }

    Some(string)
}

pub fn decode_utf8_string(atom: &str) -> Option<String> {
    let mut iter = atom.chars();
    if iter.next() != Some('"') {
        return None;
    }

    let mut string = String::new();
    loop {
        match iter.next() {
            None => return None,
            Some('"') => {
                if iter.next().is_some() {
                    return None;
                }
                break;
            }
            Some('\\') => match iter.next() {
                Some('0') => string.push('\0'),
                Some('t') => string.push('\t'),
                Some('n') => string.push('\n'),
                Some('r') => string.push('\r'),
                Some('"') => string.push('\"'),
                Some('\\') => string.push('\\'),
                Some('x') => {
                    let hex1 = hex_digit_char_to_u8(iter.next()?)?;
                    let hex2 = hex_digit_char_to_u8(iter.next()?)?;
                    let chr = (hex1 << 4) | hex2;
                    if chr > 0x7F {
                        return None;
                    }
                    string.push(char::from(chr));
                }
                Some('u') => {
                    if iter.next() != Some('{') {
                        return None;
                    }
                    let mut num_digits = 0;
                    let mut esc_chr: u32 = 0;
                    loop {
                        match iter.next() {
                            Some('}') => {
                                if num_digits == 0 {
                                    return None;
                                } else {
                                    break;
                                }
                            }
                            Some(chr) => {
                                if num_digits == 6 {
                                    return None;
                                }
                                esc_chr <<= 4;
                                esc_chr |= u32::from(hex_digit_char_to_u8(chr)?);
                                num_digits += 1;
                            }
                            None => return None,
                        }
                    }
                    string.push(char::try_from(esc_chr).ok()?);
                }
                Some(_) | None => return None,
            },
            Some(chr) => string.push(chr),
        }
    }

    Some(string)
}
