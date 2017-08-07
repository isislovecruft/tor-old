extern crate libc;

use self::libc::{c_char, c_int};
use std::ffi::CString;

extern {
    fn tor_version_as_new_as(platform: *const c_char, cutoff: *const c_char) -> c_int;
}

pub fn c_tor_version_as_new_as(platform: &str, cutoff: &str) -> bool {
    unsafe {
        let c_platform = CString::new(platform).unwrap();
        let c_cutoff = CString::new(cutoff).unwrap();

        let res: c_int = tor_version_as_new_as(c_platform.as_ptr(), c_cutoff.as_ptr());
        res == 1
    }
}

