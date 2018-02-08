// Copyright (c) 2016-2017, The Tor Project, Inc. */
// See LICENSE for licensing information */

//! Utilities for working with static strings.

use std::ffi::CStr;

/// A byte-array containing a single NUL byte (`b"\0"`).
pub const NUL_BYTE: &'static [u8] = b"\0";

/// Determine whether a byte slice has intermediate NUL bytes.
///
/// # Returns
///
/// * `true` if there are no NUL bytes in `bytes` (disregarding the final byte).
/// * `false` if there are intermediate NUL bytes.
///
/// # Panics
///
/// If the byte slice is empty.
///
/// # Examples
///
/// ```
/// use tor_util::strings::no_intermediate_nul_bytes;
///
/// assert!(no_intermediate_nul_bytes(b"o/ waving not drowning") == true);
/// assert!(no_intermediate_nul_bytes(b"\0 drowning not waving") == false);
/// ```
pub fn no_intermediate_nul_bytes(bytes: &[u8]) -> bool {
    debug_assert!(!bytes.is_empty());

    !bytes[..bytes.len() - 1].contains(&0x00)
}

/// Determine whether a byte slice is terminated with a NUL byte.
///
/// # Returns
///
/// * `true` if `bytes` is terminated with a NUL byte.
/// * `false` if it is not.
///
/// # Panics
///
/// If the byte slice is empty.
///
/// # Examples
///
/// ```
/// use tor_util::strings::terminated_with_nul_byte;
///
/// assert!(terminated_with_nul_byte(b"\0") == true);
/// assert!(terminated_with_nul_byte(b"\0 drowning not waving") == false);
/// ```
pub fn terminated_with_nul_byte(bytes: &[u8]) -> bool {
    debug_assert!(!bytes.is_empty());

    bytes[bytes.len() - 1] == 0x00
}

/// Determine if a byte slice is a C-like string.
///
/// These checks guarantee that:
///
/// 1. there are no intermediate NUL bytes
/// 2. the last byte *is* a NUL byte
///
/// # Warning
///
/// This function does _not_ guarantee that the bytes represent any valid
/// encoding such as ASCII or UTF-8.
///
/// # Examples
///
/// ```
/// # use tor_util::strings::byte_slice_is_c_like;
/// #
/// let bytes: &[u8] = b"foo bar baz";
///
/// assert!(byte_slice_is_c_like(&bytes) == false);
///
/// let bytes: &[u8] = b"foo\0bar baz";
///
/// assert!(byte_slice_is_c_like(&bytes) == false);
///
/// let bytes: &[u8] = b"foo bar baz\0";
///
/// assert!(byte_slice_is_c_like(&bytes) == true);
/// ```
pub fn byte_slice_is_c_like(bytes: &[u8]) -> bool {
    no_intermediate_nul_bytes(bytes) && terminated_with_nul_byte(bytes)
}

/// Get a static `CStr` containing a single `NUL_BYTE`.
///
/// # Examples
///
/// When used as follows in a Rust FFI function, which could be called
/// from C:
///
/// ```
/// # extern crate libc;
/// # extern crate tor_util;
/// #
/// # use tor_util::strings::empty_static_cstr;
/// use libc::c_char;
/// use std::ffi::CStr;
///
/// pub extern "C" fn give_c_code_an_empty_static_string() -> *const c_char {
///     let empty: &'static CStr = empty_static_cstr();
///
///     empty.as_ptr()
/// }
///
/// # fn main() {
/// #     give_c_code_an_empty_static_string();
/// # }
/// ```
///
/// This equates to an "empty" `const char*` static string in C.
pub fn empty_static_cstr() -> &'static CStr {
    let empty: &'static CStr;

    unsafe {
        empty = CStr::from_bytes_with_nul_unchecked(NUL_BYTE);
    }

    empty
}
