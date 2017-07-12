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
/// Modify the C documentation to give warnings-  you must also re-order the rust
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
pub extern "C" fn protover_all_supported(
    c_relay_version: *const c_char,
    missing_out: *mut *mut c_char,
) -> c_int {

    if c_relay_version.is_null() || missing_out.is_null() {
        return 1;
    }

    // Require an unsafe block to read the version from a C string. The pointer
    // is checked above to ensure it is not null.
    let c_str: &CStr;
    unsafe {
        c_str = CStr::from_ptr(c_relay_version);
    }

    let relay_version = match c_str.to_str() {
        Ok(n) => n,
        Err(_) => return 1,
    };

    let (all_are_supported, unsupported) = all_supported(relay_version);

    if all_are_supported {
        return 1;
    }

    let c_unsupported = match CString::new(unsupported) {
        Ok(n) => n,
        Err(_) => return 1,
    };

    unsafe {
        // TODO this needs to be a RustString
        *missing_out = c_unsupported.into_raw();
    }

    0
}

#[no_mangle]
pub extern "C" fn protocol_list_supports_protocol(
    c_protocol_list: *const c_char,
    c_protocol: uint32_t,
    version: uint32_t,
) -> c_int {
    if c_protocol_list.is_null() {
        return 1;
    }

    // Require an unsafe block to read the version from a C string. The pointer
    // is checked above to ensure it is not null.
    let c_str: &CStr;
    unsafe {
        c_str = CStr::from_ptr(c_protocol_list);
    }

    let protocol_list = match c_str.to_str() {
        Ok(n) => n,
        Err(_) => return 1,
    };

    let protocol = match translate_to_rust(c_protocol) {
        Ok(n) => n,
        Err(_) => return 0,
    };

    let is_supported =
        protover_string_supports_protocol(protocol_list, protocol, version);

    return if is_supported { 1 } else { 0 };
}

#[no_mangle]
pub extern "C" fn protover_get_supported_protocols() -> RustString {
    // Not handling errors when unwrapping as the content is controlled
    // and is an empty string
    let empty = RustString::from(CString::new("").unwrap());

    let supported = get_supported_protocols();
    let c_supported = match CString::new(supported) {
        Ok(n) => n,
        Err(_) => return empty,
    };

    RustString::from(c_supported)
}

#[no_mangle]
pub extern "C" fn protover_compute_vote(
    list: *const Stringlist,
    threshold: c_int,
) -> RustString {
    // Not handling errors when unwrapping as the content is controlled
    // and is an empty string
    let empty = RustString::from(CString::new("").unwrap());

    if list.is_null() {
        return empty;
    }

    // Dereference of raw pointer requires an unsafe block. The pointer is
    // checked above to ensure it is not null.
    let data: Vec<String>;
    unsafe {
        data = (*list).get_list();
    }

    let vote = compute_vote(data, threshold);
    let c_vote = match CString::new(vote) {
        Ok(n) => n,
        Err(_) => return empty,
    };

    RustString::from(c_vote)
}

#[no_mangle]
pub extern "C" fn protover_is_supported_here(
    c_protocol: uint32_t,
    version: uint32_t,
) -> c_int {
    let protocol = match translate_to_rust(c_protocol) {
        Ok(n) => n,
        Err(_) => return 0,
    };

    let is_supported = is_supported_here(protocol, version);

    return if is_supported { 1 } else { 0 };
}

#[no_mangle]
pub extern "C" fn protover_compute_for_old_tor(
    version: *const c_char,
) -> RustString {
    // Not handling errors when unwrapping as the content is controlled
    // and is an empty string
    let empty = RustString::from(CString::new("").unwrap());

    if version.is_null() {
        return empty;
    }

    // Require an unsafe block to read the version from a C string. The pointer
    // is checked above to ensure it is not null.
    let c_str: &CStr;
    unsafe {
        c_str = CStr::from_ptr(version);
    }

    let version = match c_str.to_str() {
        Ok(n) => n,
        Err(_) => return empty,
    };

    let supported = compute_for_old_tor(&version);

    let c_supported = match CString::new(supported) {
        Ok(n) => n,
        Err(_) => return empty,
    };

    RustString::from(c_supported)
}
