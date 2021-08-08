use crate::bindings;
use crate::core::ngx_core_macro;

macro_rules! ngx_linefeed {
    ($($p: expr)*) => {
        (*($($p)*)) = crate::core::ngx_core_macro::LF;
        $($p)* = ($($p)*).offset(1);
    };
}

#[inline]
pub unsafe extern "C" fn ngx_write_fd(
    mut fd: bindings::ngx_fd_t,
    mut buf: *mut libc::c_void,
    mut n: bindings::size_t,
) -> bindings::ssize_t {
    return libc::write(fd, buf, n as usize) as bindings::ssize_t;
}
