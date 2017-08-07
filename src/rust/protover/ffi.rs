extern crate libc;
extern crate smartlist;

use self::smartlist::*;
use std::fmt;
use self::libc::{c_char, c_int, int32_t};
use std::ffi::CStr;
use std::ffi::CString;

/// List of recognized subprotocols (C representation)
#[repr(C)]
#[derive(Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum ProtocolType {
    PRT_LINK,
    PRT_LINKAUTH,
    PRT_RELAY,
    PRT_DIRCACHE,
    PRT_HSDIR,
    PRT_HSINTRO,
    PRT_HSREND,
    PRT_DESC,
    PRT_MICRODESC,
    PRT_CONS,
}

fn translate_to_rust(s: ProtocolType) -> super::Proto {
    match s {
        ProtocolType::PRT_DESC => super::Proto::Desc,
        ProtocolType::PRT_CONS => super::Proto::Cons,
        ProtocolType::PRT_DIRCACHE => super::Proto::DirCache,
        ProtocolType::PRT_HSDIR => super::Proto::HSDir,
        ProtocolType::PRT_HSINTRO => super::Proto::HSIntro,
        ProtocolType::PRT_HSREND => super::Proto::HSRend,
        ProtocolType::PRT_LINK => super::Proto::Link,
        ProtocolType::PRT_LINKAUTH => super::Proto::LinkAuth,
        ProtocolType::PRT_MICRODESC => super::Proto::Microdesc,
        ProtocolType::PRT_RELAY => super::Proto::Relay,
    }
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[no_mangle]
pub unsafe extern "C" fn protover_all_supported(
    relay_vers: *const c_char,
    missing_out: *mut *mut c_char,
) -> c_int {

    if relay_vers.is_null() || missing_out.is_null() {
        return 1;
    }

    let c_str = CStr::from_ptr(relay_vers);
    let r_str = match c_str.to_str() {
        Ok(n) => n,
        Err(_) => return 1,
    };

    let (status, unsupported) = super::all_supported(r_str);

    if status == false {
        let c_unsupported = CString::new(unsupported).unwrap();
        *missing_out = c_unsupported.into_raw();
        return 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn protocol_list_supports_protocol(
    list: *const c_char,
    tp: ProtocolType,
    vers: int32_t,
) -> c_int {
    if list.is_null() {
        return 1;
    }

    let c_str = CStr::from_ptr(list);
    let r_str = match c_str.to_str() {
        Ok(n) => n,
        Err(_) => return 1,
    };

    let proto = translate_to_rust(tp);
    let is_supported = super::list_supports_protocol(r_str, proto, vers);

    return if is_supported { 1 } else { 0 };
}

// TODO this should also return a rust string
#[no_mangle]
pub unsafe extern "C" fn protover_get_supported_protocols() -> *mut c_char {
    let supported = super::get_supported_protocols();

    CString::new(supported).unwrap().into_raw()
}

// TODO this should return a rust string
#[no_mangle]
pub unsafe extern "C" fn protover_compute_vote(
    list: *mut Smartlist,
    threshold: c_int,
) -> *mut c_char {
    if list.is_null() {
        return CString::new("").unwrap().into_raw();
    }

    let data = get_list_of_strings(&*list); // TODO verify this is ok
    let vote = super::compute_vote(data, threshold);

    CString::new(vote).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn protover_is_supported_here(
    pt: ProtocolType,
    vers: int32_t,
) -> c_int {
    let proto = translate_to_rust(pt);
    let is_supported = super::is_supported_here(proto, vers);

    return if is_supported { 1 } else { 0 };
}

#[no_mangle]
pub unsafe extern "C" fn protover_compute_for_old_tor(
    vers: *const c_char,
) -> *mut c_char {
    let c_str = CStr::from_ptr(vers);
    let r_str = match c_str.to_str() {
        Ok(n) => n,
        Err(_) => return CString::new("").unwrap().into_raw(),
    };

    let supported = super::compute_for_old_tor(String::from(r_str));

    let c_supported = CString::new(supported).unwrap();
    c_supported.into_raw()
}
