//! Copyright (c) 2016-2017, The Tor Project, Inc.
//! See LICENSE for licensing information

//! Cryptographically secure random floating point number generation
//!
//! A drop-in replacement for some of Tor's cryptographically random number
//! generation functions. Also contains some extra tests.

// These are the modules we actually want to export
pub mod ffi;

mod crypto_rand_f64_sign;
pub use crypto_rand_f64_sign::*;

mod crypto_rand_distribution;
pub use crypto_rand_distribution::*;

mod tolerance_f64;
pub use tolerance_f64::*;

mod limits_f64;
pub use limits_f64::*;
