//! FFI functions, only to be called from C.
//!
//! Equivalent C versions of this api are in `src/or/protover.c`

use libc::{c_char, c_int, uint32_t};
use std::ffi::CStr;
use std::ffi::CString;

use protover::*;
use smartlist::*;
use tor_util::RustString;

/// Translate C enums to Rust Proto enums, using the integer value of the C
/// enum to map to its associated Rust enum
/// This is dependant on the associated C enum preserving ordering.
fn translate_to_rust(c_proto: uint32_t) -> Result<Proto, &'static str> {
    match c_proto {
        0 => Ok(Proto::Link),
        1 => Ok(Proto::LinkAuth),
        2 => Ok(Proto::Relay),
        3 => Ok(Proto::DirCache),
        4 => Ok(Proto::HSDir),
        5 => Ok(Proto::HSIntro),
        6 => Ok(Proto::HSRend),
        7 => Ok(Proto::Desc),
        8 => Ok(Proto::Microdesc),
        9 => Ok(Proto::Cons),
        _ => Err("Invalid protocol type"),
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
            Err(_) => return 1,
        };
        *missing_out = c_unsupported.into_raw();
        return 0;
    }
    1
}

#[no_mangle]
pub unsafe extern "C" fn protocol_list_supports_protocol(
    list: *const c_char,
    tp: uint32_t,
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

    let proto = match translate_to_rust(tp) {
        Ok(n) => n,
        Err(_) => return 0,
    };

    let is_supported = protover_string_supports_protocol(r_str, proto, vers);

    return if is_supported { 1 } else { 0 };
}

#[no_mangle]
pub unsafe extern "C" fn protover_get_supported_protocols() -> RustString {
    // unwrapping wthout handling the error is safe as the string content is
    // controlled and is simply an empty string
    let empty = RustString::from(CString::new("").unwrap());

    let supported = get_supported_protocols();
    let c_supported = match CString::new(supported) {
        Ok(n) => n,
        Err(_) => return empty,
    };
    RustString::from(c_supported)
}

#[no_mangle]
pub unsafe extern "C" fn protover_compute_vote(
    list: *const Stringlist,
    threshold: c_int,
) -> RustString {
    // Not handling errors when unwrapping as the content is controlled
    // and is an empty string
    let empty = RustString::from(CString::new("").unwrap());
    if list.is_null() {
        return empty;
    }

    let data = (*list).get_list();
    let vote = compute_vote(data, threshold);

    let c_vote = match CString::new(vote) {
        Ok(n) => n,
        Err(_) => return empty,
    };
    RustString::from(c_vote)
}

#[no_mangle]
pub unsafe extern "C" fn protover_is_supported_here(
    pt: uint32_t,
    vers: uint32_t,
) -> c_int {
    let proto = match translate_to_rust(pt) {
        Ok(n) => n,
        Err(_) => return 0,
    };
    let is_supported = is_supported_here(proto, vers);

    return if is_supported { 1 } else { 0 };
}

#[no_mangle]
pub unsafe extern "C" fn protover_compute_for_old_tor(
    vers: *const c_char,
) -> RustString {
    // Not handling errors in unwrapping as this is an empty string
    let empty = RustString::from(CString::new("").unwrap());

    let c_str = CStr::from_ptr(vers);
    let r_str = match c_str.to_str() {
        Ok(n) => n,
        Err(_) => return empty,
    };

    // compute for old tor can take a reference?
    let supported = compute_for_old_tor(String::from(r_str));

    let c_supported = match CString::new(supported) {
        Ok(n) => n,
        Err(_) => return empty,
    };
    RustString::from(c_supported)
}
