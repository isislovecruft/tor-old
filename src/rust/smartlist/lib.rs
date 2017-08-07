extern crate libc;

use std::slice;
use self::libc::{c_char};
use std::ffi::CStr;

#[repr(C)]
pub struct Smartlist {
    pub list: *const *const c_char,
    pub num_used: i8,
    pub capacity: i8,
}

pub unsafe fn get_list_of_strings(sl: &Smartlist) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    let elems = slice::from_raw_parts(sl.list, sl.num_used as usize);

    for i in elems.iter() {
        let c_str = CStr::from_ptr(*i as *const c_char);
        let r_str = c_str.to_str().unwrap();
        v.push(String::from(r_str));
    }

   v
}


#[cfg(test)]
mod test {
    #[test]
    fn test_get_list_of_strings() {
        extern crate libc;

        use std::ffi::CString;
        use libc::c_char;

        use super::Smartlist;
        use super::get_list_of_strings;

        let args = vec![String::from("a"), String::from("b")];

        let cstr_argv: Vec<_> = args.iter()
            .map(|arg| CString::new(arg.as_str()).unwrap())
            .collect();

        let p_args: Vec<_> = cstr_argv.iter().map(|arg| arg.as_ptr()).collect();

        let p: *const *const c_char = p_args.as_ptr();

        let sl = Smartlist {
            list: p,
            num_used: 2,
            capacity: 2,
        };

        unsafe {
            let data = get_list_of_strings(&sl);
            assert_eq!("a", &data[0]);
            assert_eq!("b", &data[1]);
        }
    }
}
