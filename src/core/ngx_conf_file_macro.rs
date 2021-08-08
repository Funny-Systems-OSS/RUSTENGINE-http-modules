macro_rules! NGX_CONF_UNSET_UINT {
    () => {
        (bindings::ngx_uint_t::MAX)
    };
}

macro_rules! NGX_CONF_UNSET_PTR {
    () => {
        (usize::MAX) as *mut libc::c_void
    };
}

macro_rules! NGX_CONF_UNSET_SIZE {
    () => {
        (bindings::size_t::MAX)
    };
}

macro_rules! NGX_CONF_UNSET_MSEC {
    () => {
        (-1 as bindings::ngx_msec_t)
    };
}

macro_rules! NGX_CONF_OK {
    () => {
        ptr::null_mut()
    };
}

macro_rules! NGX_CONF_ERROR {
    () => {
        (usize::MAX) as *mut libc::c_void as *mut i8
    };
}

macro_rules! ngx_conf_merge_bufs_value {
    (
        $($conf: expr)*,
        $($prev: expr)*,
        $default_num: expr,
        $default_size:expr) => {
            unsafe{
                if $($conf).*.num == 0 {
                    if $($prev).*.num != 0{
                        $($conf).*.num = $($prev).*.num;
                        $($conf).*.size = $($prev).*.size;
                    } else {
                        $($conf).*.num = $default_num;
                        $($conf).*.size = $default_size;
                    }
                }
            }
    };
}

macro_rules! ngx_null_command {
    () => {
        bindings::ngx_command_t {
            name: {
                let init = ngx_null_string!();
                init
            },
            type_: 0,
            set: None,
            conf: 0,
            offset: 0,
            post: ptr::null_mut(),
        };
    };
}
