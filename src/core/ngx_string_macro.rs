use crate::bindings;
use std::ffi;
use std::mem;
use std::ptr;

macro_rules! ngx_string {
    ($($target: expr)*) => {
        bindings::ngx_str_t {
            len: ($($target)*.len() - 1) as u64,
            data: $($target)*.as_ptr() as *mut u8
        };
    };
}

macro_rules! ngx_null_string {
    () => {
        bindings::ngx_str_t {
            len: 0,
            data: ptr::null_mut(),
        };
    };
}

macro_rules! ngx_str_set {
    ($($str_: expr)*,
    $($text: expr)*) => {
        (*$($str_).*).len = ($($text)*.len() - 1) as u64;
        (*$($str_).*).data = $($text)*.as_ptr() as *mut u8;
    }
}

macro_rules! ngx_memzero{
    ($($buf: expr)*,
    $($n: expr)*) => {
        libc::memset(
            ($($buf).*) as *mut _ as *mut libc::c_void,
            0,
            $($n).*
        );
    };
}

pub fn ngx_memcpy(dst: *mut u8, src: *mut u8, n: usize) -> *mut u8 {
    if dst.is_null() || src.is_null() {
        panic!(
            "source ({:#?}) or destination ({:#?}) may be null.",
            src, dst,
        );
    }
    return unsafe {
        libc::memcpy(
            dst as *mut libc::c_void,
            src as *const libc::c_void,
            n as libc::size_t,
        ) as *mut u8
    };
}

pub fn ngx_cpymem(dst: *mut u8, src: *mut u8, n: usize) -> *mut u8 {
    let dst_ptr = ngx_memcpy(dst, src, n);
    return dst_ptr.wrapping_offset(n as isize) as *mut u8;
}

macro_rules! ngx_strncmp {
    ($($s1: expr)*,
    $($s2: expr)*,
    $($n: expr)*) => {
        libc::strncmp(
            $($s1).* as *const i8,
            $($s2).* as *const i8,
            $($n).* as usize);
    };
}

macro_rules! ngx_strcmp {
    ($($s1: expr)*,
    $($s2: expr)*) => {
        libc::strcmp(
            $($s1).* as *const i8,
            $($s2).* as *const i8);
    };
}
