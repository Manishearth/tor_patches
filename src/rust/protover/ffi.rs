//! FFI functions, only to be called from C.
//!
//! Equivalent C versions of this api are in `src/or/protover.c`

use smartlist::*;

use tor_util::RustString;

use std::fmt;
use libc::{c_char, c_int, uint32_t};
use std::ffi::CStr;
use std::ffi::CString;

// import from protover library
use protover::Proto;
use protover::all_supported;
use protover::protover_string_supports_protocol;
use protover::get_supported_protocols;
use protover::compute_vote;
use protover::is_supported_here;
use protover::compute_for_old_tor;

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

fn translate_to_rust(s: ProtocolType) -> Proto {
    match s {
        ProtocolType::PRT_DESC => Proto::Desc,
        ProtocolType::PRT_CONS => Proto::Cons,
        ProtocolType::PRT_DIRCACHE => Proto::DirCache,
        ProtocolType::PRT_HSDIR => Proto::HSDir,
        ProtocolType::PRT_HSINTRO => Proto::HSIntro,
        ProtocolType::PRT_HSREND => Proto::HSRend,
        ProtocolType::PRT_LINK => Proto::Link,
        ProtocolType::PRT_LINKAUTH => Proto::LinkAuth,
        ProtocolType::PRT_MICRODESC => Proto::Microdesc,
        ProtocolType::PRT_RELAY => Proto::Relay,
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

    let (status, unsupported) = all_supported(r_str);

    if status == false {
        let c_unsupported = match CString::new(unsupported) {
            Ok(n) => n,
            Err(_) => panic!("invalid protocol string!"),
        };
        *missing_out = c_unsupported.into_raw();
        return 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn protocol_list_supports_protocol(
    list: *const c_char,
    tp: ProtocolType,
    vers: uint32_t,
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
    let is_supported = protover_string_supports_protocol(r_str, proto, vers);

    return if is_supported { 1 } else { 0 };
}

#[no_mangle]
pub unsafe extern "C" fn protover_get_supported_protocols() -> RustString {
    let supported = get_supported_protocols();
    let c_supported = match CString::new(supported) {
        Ok(n) => n,
        Err(_) => panic!("invalid supported protocol string"),
    };
    RustString::from(c_supported)
}

#[no_mangle]
pub unsafe extern "C" fn protover_compute_vote(
    list: *mut Smartlist,
    threshold: c_int,
) -> RustString {
    if list.is_null() {
        // Not handling errors in unwrapping as this is an empty string
        return RustString::from(CString::new("").unwrap());
    }

    let data = get_list_of_strings(&*list); // TODO verify this is ok
    let vote = compute_vote(data, threshold);

    let c_vote = match CString::new(vote) {
        Ok(n) => n,
        Err(_) => panic!("invalid strings in computed vote"),
    };
    RustString::from(c_vote)
}

#[no_mangle]
pub unsafe extern "C" fn protover_is_supported_here(
    pt: ProtocolType,
    vers: uint32_t,
) -> c_int {
    let proto = translate_to_rust(pt);
    let is_supported = is_supported_here(proto, vers);

    return if is_supported { 1 } else { 0 };
}

#[no_mangle]
pub unsafe extern "C" fn protover_compute_for_old_tor(
    vers: *const c_char,
) -> *mut c_char {
    let c_str = CStr::from_ptr(vers);
    let r_str = match c_str.to_str() {
        Ok(n) => n,
        // Not handling errors in unwrapping as this is an empty string
        Err(_) => return CString::new("").unwrap().into_raw(),
    };

    let supported = compute_for_old_tor(String::from(r_str));

    let c_supported = match CString::new(supported) {
        Ok(n) => n,
        Err(_) => panic!("invalid strings in computed vote for old tor"),
    };
    c_supported.into_raw()
}
