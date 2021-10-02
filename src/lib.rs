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
//! The minimum Rust version required by this crate is 1.36.

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

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(test)]
mod tests;

// Encode
/// Returns `"true"` if `value` is `true`,
/// otherwise returns `"false"`.
pub fn encode_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

macro_rules! encode_signed_int {
    ($sint:ident, $uint:ident, $value:expr, $output:expr) => {
        let mut remaining_digits: $uint = {
            if $value < 0 {
                $output.push('-');
                $value.wrapping_neg() as $uint
            } else {
                $value as $uint
            }
        };
        let digits_beginning = $output.len();
        loop {
            #[allow(trivial_numeric_casts)]
            let current_digit = (remaining_digits % 10) as u8;
            remaining_digits /= 10;
            $output.insert(digits_beginning, char::from(current_digit + b'0'));
            if remaining_digits == 0 {
                break;
            }
        }
    };
}

pub fn encode_i8_into(value: i8, output: &mut String) {
    encode_signed_int!(i8, u8, value, output);
}

#[inline]
pub fn encode_i8(value: i8) -> String {
    let mut output = String::new();
    encode_i8_into(value, &mut output);
    output
}

pub fn encode_i16_into(value: i16, output: &mut String) {
    encode_signed_int!(i16, u16, value, output);
}

#[inline]
pub fn encode_i16(value: i16) -> String {
    let mut output = String::new();
    encode_i16_into(value, &mut output);
    output
}

pub fn encode_i32_into(value: i32, output: &mut String) {
    encode_signed_int!(i32, u32, value, output);
}

#[inline]
pub fn encode_i32(value: i32) -> String {
    let mut output = String::new();
    encode_i32_into(value, &mut output);
    output
}

pub fn encode_i64_into(value: i64, output: &mut String) {
    encode_signed_int!(i64, u64, value, output);
}

#[inline]
pub fn encode_i64(value: i64) -> String {
    let mut output = String::new();
    encode_i64_into(value, &mut output);
    output
}

pub fn encode_i128_into(value: i128, output: &mut String) {
    encode_signed_int!(i128, u128, value, output);
}

#[inline]
pub fn encode_i128(value: i128) -> String {
    let mut output = String::new();
    encode_i128_into(value, &mut output);
    output
}

macro_rules! encode_unsigned_int {
    ($uint:ident, $value:expr, $output:expr) => {
        let mut remaining_digits: $uint = $value;
        let digits_beginning = $output.len();
        loop {
            #[allow(trivial_numeric_casts)]
            let current_digit = (remaining_digits % 10) as u8;
            remaining_digits /= 10;
            $output.insert(digits_beginning, char::from(current_digit + b'0'));
            if remaining_digits == 0 {
                break;
            }
        }
    };
}

pub fn encode_u8_into(value: u8, output: &mut String) {
    encode_unsigned_int!(u8, value, output);
}

#[inline]
pub fn encode_u8(value: u8) -> String {
    let mut output = String::new();
    encode_u8_into(value, &mut output);
    output
}

pub fn encode_u16_into(value: u16, output: &mut String) {
    encode_unsigned_int!(u16, value, output);
}

#[inline]
pub fn encode_u16(value: u16) -> String {
    let mut output = String::new();
    encode_u16_into(value, &mut output);
    output
}

pub fn encode_u32_into(value: u32, output: &mut String) {
    encode_unsigned_int!(u32, value, output);
}

#[inline]
pub fn encode_u32(value: u32) -> String {
    let mut output = String::new();
    encode_u32_into(value, &mut output);
    output
}

pub fn encode_u64_into(value: u64, output: &mut String) {
    encode_unsigned_int!(u64, value, output);
}

#[inline]
pub fn encode_u64(value: u64) -> String {
    let mut output = String::new();
    encode_u64_into(value, &mut output);
    output
}

pub fn encode_u128_into(value: u128, output: &mut String) {
    encode_unsigned_int!(u128, value, output);
}

#[inline]
pub fn encode_u128(value: u128) -> String {
    let mut output = String::new();
    encode_u128_into(value, &mut output);
    output
}

fn reformat_float(s: &str, output: &mut String) {
    if s == "NaN" || s == "inf" || s == "-inf" {
        output.push_str(s);
        return;
    }

    const ZEROS_THRESHOLD: u32 = 9;
    if let Some(mut remaining) = s.strip_prefix("0.") {
        let mut exp_abs: u32 = 1;
        while let Some(new_remaining) = remaining.strip_prefix('0') {
            remaining = new_remaining;
            exp_abs += 1;
        }
        if exp_abs > ZEROS_THRESHOLD {
            output.push_str(&remaining[..1]);
            if remaining.len() > 1 {
                output.push('.');
                output.push_str(&remaining[1..]);
            } else {
                output.push_str(".0");
            }
            output.push_str("e-");
            encode_u32_into(exp_abs, output);
        } else {
            output.push_str(s);
        }
    } else {
        let s = s.strip_suffix(".0").unwrap_or(s);
        if s.contains('.') {
            output.push_str(s);
        } else {
            let mut remaining = s;
            let mut num_zeros: u32 = 0;
            while let Some(new_remaining) = remaining.strip_suffix('0') {
                remaining = new_remaining;
                num_zeros += 1;
            }
            if num_zeros > ZEROS_THRESHOLD {
                output.push_str(&remaining[..1]);
                if remaining.len() > 1 {
                    output.push('.');
                    output.push_str(&remaining[1..]);
                } else {
                    output.push_str(".0");
                }
                output.push('e');
                encode_u32_into(num_zeros + (remaining.len() as u32 - 1), output);
            } else {
                output.push_str(s);
                output.push_str(".0");
            }
        }
    }
}

pub fn encode_f32_into(value: f32, output: &mut String) {
    reformat_float(&alloc::format!("{}", value), output)
}

#[inline]
pub fn encode_f32(value: f32) -> String {
    let mut output = String::new();
    encode_f32_into(value, &mut output);
    output
}

pub fn encode_f64_into(value: f64, output: &mut String) {
    reformat_float(&alloc::format!("{}", value), output)
}

#[inline]
pub fn encode_f64(value: f64) -> String {
    let mut output = String::new();
    encode_f64_into(value, &mut output);
    output
}

fn nibble_to_hex(nibble: u8) -> char {
    if nibble < 10 {
        char::from(b'0' + nibble)
    } else {
        char::from(b'a' + nibble - 10)
    }
}

pub fn encode_byte_string_into(string: &[u8], output: &mut String) {
    output.push('"');
    for &chr in string {
        #[allow(clippy::match_overlapping_arm)]
        match chr {
            b'\0' => output.push_str("\\0"),
            b'\t' => output.push_str("\\t"),
            b'\n' => output.push_str("\\n"),
            b'\r' => output.push_str("\\r"),
            b'"' => output.push_str("\\\""),
            b'\\' => output.push_str("\\\\"),
            0x20..=0x7E => output.push(char::from(chr)),
            _ => {
                output.push_str("\\x");
                output.push(nibble_to_hex(chr >> 4));
                output.push(nibble_to_hex(chr & 0xF));
            }
        }
    }
    output.push('"');
}

#[inline]
pub fn encode_byte_string(string: &[u8]) -> String {
    let mut output = String::new();
    encode_byte_string_into(string, &mut output);
    output
}

pub fn encode_ascii_string_into(string: &str, output: &mut String) {
    output.push('"');
    for &chr in string.as_bytes() {
        #[allow(clippy::match_overlapping_arm)]
        match chr {
            b'\0' => output.push_str("\\0"),
            b'\t' => output.push_str("\\t"),
            b'\n' => output.push_str("\\n"),
            b'\r' => output.push_str("\\r"),
            b'"' => output.push_str("\\\""),
            b'\\' => output.push_str("\\\\"),
            0x20..=0x7E => output.push(char::from(chr)),
            _ => {
                assert!(chr <= 0x7F, "Invalid ASCII character");
                output.push_str("\\x");
                output.push(nibble_to_hex(chr >> 4));
                output.push(nibble_to_hex(chr & 0xF));
            }
        }
    }
    output.push('"');
}

#[inline]
pub fn encode_ascii_string(string: &str) -> String {
    let mut output = String::new();
    encode_ascii_string_into(string, &mut output);
    output
}

pub fn encode_utf8_string_into(string: &str, output: &mut String) {
    output.push('"');
    for chr in string.chars() {
        match chr {
            '\0' => output.push_str("\\0"),
            '\t' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\x20'..='\x7E' => output.push(chr),
            _ => {
                output.push_str("\\u{");
                let code_beginning = output.len();
                let mut remaining_digits = u32::from(chr);
                loop {
                    output.insert(
                        code_beginning,
                        nibble_to_hex((remaining_digits & 0xF) as u8),
                    );
                    remaining_digits >>= 4;
                    if remaining_digits == 0 {
                        break;
                    }
                }
                output.push('}');
            }
        }
    }
    output.push('"');
}

#[inline]
pub fn encode_utf8_string(string: &str) -> String {
    let mut output = String::new();
    encode_utf8_string_into(string, &mut output);
    output
}

// Decode
/// Returns `Some(true)` if `atom == "true"`,
/// `Some(false)` if `atom == "false"`, or `None`
/// otherwise.
pub fn decode_bool(atom: &str) -> Option<bool> {
    match atom {
        "false" => Some(false),
        "true" => Some(true),
        _ => None,
    }
}

#[inline]
pub fn decode_i8(atom: &str) -> Option<i8> {
    atom.parse().ok()
}

#[inline]
pub fn decode_i16(atom: &str) -> Option<i16> {
    atom.parse().ok()
}

#[inline]
pub fn decode_i32(atom: &str) -> Option<i32> {
    atom.parse().ok()
}

#[inline]
pub fn decode_i64(atom: &str) -> Option<i64> {
    atom.parse().ok()
}

#[inline]
pub fn decode_i128(atom: &str) -> Option<i128> {
    atom.parse().ok()
}

#[inline]
pub fn decode_u8(atom: &str) -> Option<u8> {
    atom.parse().ok()
}

#[inline]
pub fn decode_u16(atom: &str) -> Option<u16> {
    atom.parse().ok()
}

#[inline]
pub fn decode_u32(atom: &str) -> Option<u32> {
    atom.parse().ok()
}

#[inline]
pub fn decode_u64(atom: &str) -> Option<u64> {
    atom.parse().ok()
}

#[inline]
pub fn decode_u128(atom: &str) -> Option<u128> {
    atom.parse().ok()
}

pub fn decode_f32(atom: &str) -> Option<f32> {
    if atom == "+NaN" || atom == "-NaN" {
        None
    } else {
        atom.parse().ok()
    }
}

pub fn decode_f64(atom: &str) -> Option<f64> {
    if atom == "+NaN" || atom == "-NaN" {
        None
    } else {
        atom.parse().ok()
    }
}

fn hex_digit_to_u8(chr: char) -> Option<u8> {
    match chr {
        '0'..='9' => Some(chr as u8 - b'0'),
        'A'..='F' => Some(chr as u8 - b'A' + 10),
        'a'..='f' => Some(chr as u8 - b'a' + 10),
        _ => None,
    }
}

pub fn decode_byte_string(atom: &str) -> Option<Vec<u8>> {
    enum State {
        Beginning,
        Normal,
        AfterBackslash,
        HexEscape1,
        HexEscape2(u8),
        Ending,
    }

    let mut string = Vec::new();

    let mut iter = atom.chars();
    let mut state = State::Beginning;
    loop {
        match state {
            State::Beginning => match iter.next() {
                Some('"') => state = State::Normal,
                Some(_) | None => return None,
            },
            State::Normal => match iter.next() {
                Some('\\') => state = State::AfterBackslash,
                Some('"') => state = State::Ending,
                Some(chr) => {
                    let mut utf8_buf = [0; 4];
                    string.extend_from_slice(chr.encode_utf8(&mut utf8_buf).as_bytes());
                }
                None => return None,
            },
            State::AfterBackslash => match iter.next() {
                Some('0') => {
                    string.push(b'\0');
                    state = State::Normal;
                }
                Some('t') => {
                    string.push(b'\t');
                    state = State::Normal;
                }
                Some('n') => {
                    string.push(b'\n');
                    state = State::Normal;
                }
                Some('r') => {
                    string.push(b'\r');
                    state = State::Normal;
                }
                Some('"') => {
                    string.push(b'"');
                    state = State::Normal;
                }
                Some('\\') => {
                    string.push(b'\\');
                    state = State::Normal;
                }
                Some('x') => {
                    state = State::HexEscape1;
                }
                Some(_) | None => return None,
            },
            State::HexEscape1 => match iter.next() {
                Some(chr) => {
                    let hex1 = hex_digit_to_u8(chr)?;
                    state = State::HexEscape2(hex1);
                }
                None => return None,
            },
            State::HexEscape2(hex1) => match iter.next() {
                Some(chr) => {
                    let hex2 = hex_digit_to_u8(chr)?;
                    string.push((hex1 << 4) | hex2);
                    state = State::Normal;
                }
                None => return None,
            },
            State::Ending => match iter.next() {
                None => return Some(string),
                _ => return None,
            },
        }
    }
}

pub fn decode_ascii_string(atom: &str) -> Option<String> {
    enum State {
        Beginning,
        Normal,
        AfterBackslash,
        HexEscape1,
        HexEscape2(u8),
        Ending,
    }

    let mut string = String::new();

    let mut iter = atom.chars();
    let mut state = State::Beginning;
    loop {
        match state {
            State::Beginning => match iter.next() {
                Some('"') => state = State::Normal,
                Some(_) | None => return None,
            },
            State::Normal => match iter.next() {
                Some('\\') => state = State::AfterBackslash,
                Some('"') => state = State::Ending,
                Some(chr @ '\x00'..='\x7F') => string.push(chr),
                Some(_) | None => return None,
            },
            State::AfterBackslash => match iter.next() {
                Some('0') => {
                    string.push('\0');
                    state = State::Normal;
                }
                Some('t') => {
                    string.push('\t');
                    state = State::Normal;
                }
                Some('n') => {
                    string.push('\n');
                    state = State::Normal;
                }
                Some('r') => {
                    string.push('\r');
                    state = State::Normal;
                }
                Some('"') => {
                    string.push('"');
                    state = State::Normal;
                }
                Some('\\') => {
                    string.push('\\');
                    state = State::Normal;
                }
                Some('x') => {
                    state = State::HexEscape1;
                }
                Some(_) | None => return None,
            },
            State::HexEscape1 => match iter.next() {
                Some(chr) => {
                    let hex1 = hex_digit_to_u8(chr)?;
                    state = State::HexEscape2(hex1);
                }
                None => return None,
            },
            State::HexEscape2(hex1) => match iter.next() {
                Some(chr) => {
                    let hex2 = hex_digit_to_u8(chr)?;
                    let chr = (hex1 << 4) | hex2;
                    if chr > 0x7F {
                        return None;
                    }
                    string.push(char::from(chr));
                    state = State::Normal;
                }
                None => return None,
            },
            State::Ending => match iter.next() {
                None => return Some(string),
                _ => return None,
            },
        }
    }
}

pub fn decode_utf8_string(atom: &str) -> Option<String> {
    enum State {
        Beginning,
        Normal,
        AfterBackslash,
        HexEscape1,
        HexEscape2(u8),
        UnicodeEscape1,
        UnicodeEscape2,
        UnicodeEscape3(u32),
        Ending,
    }

    let mut string = String::new();

    let mut iter = atom.chars();
    let mut state = State::Beginning;
    loop {
        match state {
            State::Beginning => match iter.next() {
                Some('"') => state = State::Normal,
                Some(_) | None => return None,
            },
            State::Normal => match iter.next() {
                Some('\\') => state = State::AfterBackslash,
                Some('"') => state = State::Ending,
                Some(chr) => string.push(chr),
                None => return None,
            },
            State::AfterBackslash => match iter.next() {
                Some('0') => {
                    string.push('\0');
                    state = State::Normal;
                }
                Some('t') => {
                    string.push('\t');
                    state = State::Normal;
                }
                Some('n') => {
                    string.push('\n');
                    state = State::Normal;
                }
                Some('r') => {
                    string.push('\r');
                    state = State::Normal;
                }
                Some('"') => {
                    string.push('"');
                    state = State::Normal;
                }
                Some('\\') => {
                    string.push('\\');
                    state = State::Normal;
                }
                Some('x') => {
                    state = State::HexEscape1;
                }
                Some('u') => {
                    state = State::UnicodeEscape1;
                }
                Some(_) | None => return None,
            },
            State::HexEscape1 => match iter.next() {
                Some(chr) => {
                    let hex1 = hex_digit_to_u8(chr)?;
                    state = State::HexEscape2(hex1);
                }
                None => return None,
            },
            State::HexEscape2(hex1) => match iter.next() {
                Some(chr) => {
                    let hex2 = hex_digit_to_u8(chr)?;
                    let chr = (hex1 << 4) | hex2;
                    if chr > 0x7F {
                        return None;
                    }
                    string.push(char::from(chr));
                    state = State::Normal;
                }
                None => return None,
            },
            State::UnicodeEscape1 => match iter.next() {
                Some('{') => state = State::UnicodeEscape2,
                Some(_) | None => return None,
            },
            State::UnicodeEscape2 => match iter.next() {
                Some(chr) => {
                    let hex1 = hex_digit_to_u8(chr)?;
                    state = State::UnicodeEscape3(u32::from(hex1));
                }
                None => return None,
            },
            State::UnicodeEscape3(current_hex) => match iter.next() {
                Some('}') => {
                    string.push(core::char::from_u32(current_hex)?);
                    state = State::Normal;
                }
                Some(chr) => {
                    if current_hex >= 0x1000_0000 {
                        return None;
                    }
                    let new_digit = u32::from(hex_digit_to_u8(chr)?);
                    state = State::UnicodeEscape3((current_hex << 4) | new_digit);
                }
                None => return None,
            },
            State::Ending => match iter.next() {
                None => return Some(string),
                _ => return None,
            },
        }
    }
}
