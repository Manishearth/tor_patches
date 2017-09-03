use std::slice;
use libc::c_char;
use std::ffi::CStr;

/// Smartlists are a type used in C code in tor to define a collection of a
/// generic type, which has a capacity and a number used. Each Smartlist
/// defines how to extract the list of values from the underlying C structure
/// Implementations are required to have a C representation
pub trait Smartlist<T> {
    unsafe fn get_list(&self) -> Vec<T>;
}
#[repr(C)]
pub struct Stringlist {
    pub list: *const *const c_char,
    pub num_used: u8,
    pub capacity: u8,
}

impl Smartlist<String> for Stringlist {
    unsafe fn get_list(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        let elems = slice::from_raw_parts(self.list, self.num_used as usize);

        for i in elems.iter() {
            let c_str = CStr::from_ptr(*i as *const c_char);
            let r_str = match c_str.to_str() {
                Ok(n) => n,
                Err(_) => panic!("invalid smartlist string value"),
            };
            v.push(String::from(r_str));
        }

        v
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test_get_list_of_strings() {
        extern crate libc;

        use std::ffi::CString;
        use libc::c_char;

        use super::Smartlist;
        use super::Stringlist;

        let args = vec![String::from("a"), String::from("b")];

        // for each string, transform  it into a CString
        let c_strings: Vec<_> = args.iter()
            .map(|arg| CString::new(arg.as_str()).unwrap())
            .collect();

        // then, collect a pointer for each CString
        let p_args: Vec<_> = c_strings.iter().map(|arg| arg.as_ptr()).collect();

        // then, collect a pointer for the list itself
        let p: *const *const c_char = p_args.as_ptr();

        let sl = Stringlist {
            list: p,
            num_used: 2,
            capacity: 2,
        };

        unsafe {
            let data = sl.get_list();
            assert_eq!("a", &data[0]);
            assert_eq!("b", &data[1]);
        }
    }
}
