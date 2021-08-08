use crate::bindings;
use crate::core::ngx_array_macro;
use crate::core::ngx_conf_file_macro;
use crate::core::ngx_module_macro;
use crate::core::ngx_string_macro;
use std::mem;
use std::ptr;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngx_http_header_val_s {
    pub value: bindings::ngx_http_complex_value_t,
    pub key: bindings::ngx_str_t,
    pub handler: ngx_http_set_header_pt,
    pub offset: bindings::ngx_uint_t,
    pub always: bindings::ngx_uint_t,
}

pub type ngx_http_set_header_pt = Option<
    unsafe extern "C" fn(
        r: *mut bindings::ngx_http_request_t,
        hv: *mut ngx_http_header_val_t,
        value: *mut bindings::ngx_str_t,
    ) -> bindings::ngx_int_t,
>;

pub type ngx_http_header_val_t = ngx_http_header_val_s;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ngx_http_set_header_t {
    pub name: bindings::ngx_str_t,
    pub offset: bindings::ngx_uint_t,
    pub handler: ngx_http_set_header_pt,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ngx_http_expires_t {
    NGX_HTTP_EXPIRES_OFF,
    NGX_HTTP_EXPIRES_EPOCH,
    NGX_HTTP_EXPIRES_MAX,
    NGX_HTTP_EXPIRES_ACCESS,
    NGX_HTTP_EXPIRES_MODIFIED,
    NGX_HTTP_EXPIRES_DAILY,
    NGX_HTTP_EXPIRES_UNSET,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ngx_http_headers_conf_t {
    pub expires: ngx_http_expires_t,
    pub expires_time: bindings::time_t,
    pub expires_value: *mut bindings::ngx_http_complex_value_t,
    pub headers: *mut bindings::ngx_array_t,
    pub trailers: *mut bindings::ngx_array_t,
}

// Initialized in run_static_initializers
static mut ngx_http_set_headers: [ngx_http_set_header_t; 5] = [ngx_http_set_header_t {
    name: bindings::ngx_str_t {
        len: 0,
        data: ptr::null_mut(),
    },
    offset: 0,
    handler: None,
}; 5];

// Initialized in run_static_initializers
static mut ngx_http_headers_filter_commands: [bindings::ngx_command_t; 4] =
    [bindings::ngx_command_t {
        name: bindings::ngx_str_t {
            len: 0,
            data: ptr::null_mut(),
        },
        type_: 0,
        set: None,
        conf: 0,
        offset: 0,
        post: ptr::null_mut(),
    }; 4];

static mut ngx_http_headers_filter_module_ctx: bindings::ngx_http_module_t = {
    let init = bindings::ngx_http_module_t {
        preconfiguration: None,
        postconfiguration: Some(ngx_http_headers_filter_init),
        create_main_conf: None,
        init_main_conf: None,
        create_srv_conf: None,
        merge_srv_conf: None,
        create_loc_conf: Some(ngx_http_headers_create_conf),
        merge_loc_conf: Some(ngx_http_headers_merge_conf),
    };
    init
};
#[no_mangle]

pub static mut ngx_http_headers_filter_module: bindings::ngx_module_t = unsafe {
    {
        let init = bindings::ngx_module_t {
            ctx_index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as bindings::ngx_uint_t,
            index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as bindings::ngx_uint_t,
            name: ptr::null_mut(),
            spare0: 0,
            spare1: 0,
            version: bindings::nginx_version as bindings::ngx_uint_t,
            signature: ngx_module_macro::NGX_MODULE_SIGNATURE as *const u8 as *const libc::c_char,
            ctx: &ngx_http_headers_filter_module_ctx as *const bindings::ngx_http_module_t
                as *mut bindings::ngx_http_module_t as *mut libc::c_void,
            commands: ngx_http_headers_filter_commands.as_ptr() as *mut _,
            type_: bindings::NGX_HTTP_MODULE as bindings::ngx_uint_t,
            init_master: None,
            init_module: None,
            init_process: None,
            init_thread: None,
            exit_thread: None,
            exit_process: None,
            exit_master: None,
            spare_hook0: 0,
            spare_hook1: 0,
            spare_hook2: 0,
            spare_hook3: 0,
            spare_hook4: 0,
            spare_hook5: 0,
            spare_hook6: 0,
            spare_hook7: 0,
        };
        init
    }
};

static mut ngx_http_next_header_filter: bindings::ngx_http_output_header_filter_pt = None;

static mut ngx_http_next_body_filter: bindings::ngx_http_output_body_filter_pt = None;

unsafe extern "C" fn ngx_http_headers_filter(
    mut r: *mut bindings::ngx_http_request_t,
) -> bindings::ngx_int_t {
    let mut value = bindings::ngx_str_t {
        len: 0,
        data: ptr::null_mut(),
    };
    let mut i: bindings::ngx_uint_t = 0;
    let mut safe_status: bindings::ngx_uint_t = 0;
    let mut h = 0 as *mut ngx_http_header_val_t;
    let mut conf = 0 as *mut ngx_http_headers_conf_t;

    if r != (*r).main {
        return ngx_http_next_header_filter.expect("non-null function pointer")(r);
    }

    conf = *ngx_http_get_module_loc_conf!(r, ngx_http_headers_filter_module)
        as *mut ngx_http_headers_conf_t;

    if (*conf).expires == ngx_http_expires_t::NGX_HTTP_EXPIRES_OFF
        && (*conf).headers.is_null()
        && (*conf).trailers.is_null()
    {
        return ngx_http_next_header_filter.expect("non-null function pointer")(r);
    }

    match (*r).headers_out.status as i32 {
        bindings::NGX_HTTP_OK
        | bindings::NGX_HTTP_CREATED
        | bindings::NGX_HTTP_NO_CONTENT
        | bindings::NGX_HTTP_PARTIAL_CONTENT
        | bindings::NGX_HTTP_MOVED_PERMANENTLY
        | bindings::NGX_HTTP_MOVED_TEMPORARILY
        | bindings::NGX_HTTP_SEE_OTHER
        | bindings::NGX_HTTP_NOT_MODIFIED
        | bindings::NGX_HTTP_TEMPORARY_REDIRECT
        | bindings::NGX_HTTP_PERMANENT_REDIRECT => safe_status = 1,
        _ => safe_status = 0,
    }

    if (*conf).expires != ngx_http_expires_t::NGX_HTTP_EXPIRES_OFF && safe_status != 0 {
        if ngx_http_set_expires(r, conf) != bindings::NGX_OK as isize {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }
    }

    if !(*conf).headers.is_null() {
        h = (*(*conf).headers).elts as *mut ngx_http_header_val_t;
        i = 0;
        while i < (*(*conf).headers).nelts {
            if !(safe_status == 0 && (*h.offset(i as isize)).always == 0) {
                if bindings::ngx_http_complex_value(
                    r,
                    &mut (*h.offset(i as isize)).value,
                    &mut value,
                ) != bindings::NGX_OK as isize
                {
                    return bindings::NGX_ERROR as bindings::ngx_int_t;
                }
                if (*h.offset(i as isize))
                    .handler
                    .expect("non-null function pointer")(
                    r, &mut *h.offset(i as isize), &mut value
                ) != bindings::NGX_OK as isize
                {
                    return bindings::NGX_ERROR as bindings::ngx_int_t;
                }
            }
            i = i.wrapping_add(1);
        }
    }
    if !(*conf).trailers.is_null() {
        h = (*(*conf).trailers).elts as *mut ngx_http_header_val_t;
        i = 0;
        while i < (*(*conf).trailers).nelts {
            if safe_status == 0 && (*h.offset(i as isize)).always == 0 {
                i = i.wrapping_add(1)
            } else {
                (*r).set_expect_trailers(1);
                break;
            }
        }
    }
    return ngx_http_next_header_filter.expect("non-null function pointer")(r);
}

unsafe extern "C" fn ngx_http_trailers_filter(
    mut r: *mut bindings::ngx_http_request_t,
    mut in_: *mut bindings::ngx_chain_t,
) -> bindings::ngx_int_t {
    let mut value = bindings::ngx_str_t {
        len: 0,
        data: ptr::null_mut(),
    };
    let mut i: bindings::ngx_uint_t = 0;
    let mut safe_status: bindings::ngx_uint_t = 0;
    let mut cl = 0 as *mut bindings::ngx_chain_t;
    let mut t = 0 as *mut bindings::ngx_table_elt_t;
    let mut h = 0 as *mut ngx_http_header_val_t;
    let mut conf = 0 as *mut ngx_http_headers_conf_t;

    conf = *ngx_http_get_module_loc_conf!(r, ngx_http_headers_filter_module)
        as *mut ngx_http_headers_conf_t;

    if in_.is_null()
        || (*conf).trailers.is_null()
        || (*r).expect_trailers() == 0
        || (*r).header_only() != 0
    {
        return ngx_http_next_body_filter.expect("non-null function pointer")(r, in_);
    }

    cl = in_;
    while !cl.is_null() {
        if (*(*cl).buf).last_buf() != 0 {
            break;
        }
        cl = (*cl).next;
    }

    if cl.is_null() {
        return ngx_http_next_body_filter.expect("non-null function pointer")(r, in_);
    }

    match (*r).headers_out.status as i32 {
        bindings::NGX_HTTP_OK
        | bindings::NGX_HTTP_CREATED
        | bindings::NGX_HTTP_NO_CONTENT
        | bindings::NGX_HTTP_PARTIAL_CONTENT
        | bindings::NGX_HTTP_MOVED_PERMANENTLY
        | bindings::NGX_HTTP_MOVED_TEMPORARILY
        | bindings::NGX_HTTP_SEE_OTHER
        | bindings::NGX_HTTP_NOT_MODIFIED
        | bindings::NGX_HTTP_TEMPORARY_REDIRECT
        | bindings::NGX_HTTP_PERMANENT_REDIRECT => safe_status = 1,
        _ => safe_status = 0,
    }

    h = (*(*conf).trailers).elts as *mut ngx_http_header_val_t;
    i = 0;
    while i < (*(*conf).trailers).nelts {
        if !(safe_status == 0 && (*h.offset(i as isize)).always == 0) {
            if bindings::ngx_http_complex_value(r, &mut (*h.offset(i as isize)).value, &mut value)
                != bindings::NGX_OK as isize
            {
                return bindings::NGX_ERROR as bindings::ngx_int_t;
            }
            if value.len != 0 {
                t = bindings::ngx_list_push(&mut (*r).headers_out.trailers)
                    as *mut bindings::ngx_table_elt_t;
                if t.is_null() {
                    return bindings::NGX_ERROR as bindings::ngx_int_t;
                }
                (*t).key = (*h.offset(i as isize)).key;
                (*t).value = value;
                (*t).hash = 1;
            }
        }
        i = i.wrapping_add(1);
    }
    return ngx_http_next_body_filter.expect("non-null function pointer")(r, in_);
}

unsafe extern "C" fn ngx_http_set_expires(
    mut r: *mut bindings::ngx_http_request_t,
    mut conf: *mut ngx_http_headers_conf_t,
) -> bindings::ngx_int_t {
    let mut err = 0 as *mut i8;
    let mut len: bindings::size_t = 0;
    let mut now: bindings::time_t = 0;
    let mut expires_time: bindings::time_t = 0;
    let mut max_age: bindings::time_t = 0;
    let mut value = bindings::ngx_str_t {
        len: 0,
        data: ptr::null_mut(),
    };
    let mut rc: bindings::ngx_int_t = 0;
    let mut i: bindings::ngx_uint_t = 0;
    let mut e = 0 as *mut bindings::ngx_table_elt_t;
    let mut cc = 0 as *mut bindings::ngx_table_elt_t;
    let mut ccp = 0 as *mut *mut bindings::ngx_table_elt_t;
    let mut expires = ngx_http_expires_t::NGX_HTTP_EXPIRES_OFF;

    expires = (*conf).expires;
    expires_time = (*conf).expires_time;

    if !(*conf).expires_value.is_null() {
        if bindings::ngx_http_complex_value(r, (*conf).expires_value, &mut value)
            != bindings::NGX_OK as isize
        {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }
        rc = ngx_http_parse_expires(&mut value, &mut expires, &mut expires_time, &mut err);
        if rc != bindings::NGX_OK as isize {
            return bindings::NGX_OK as bindings::ngx_int_t;
        }
        if expires == ngx_http_expires_t::NGX_HTTP_EXPIRES_OFF {
            return bindings::NGX_OK as bindings::ngx_int_t;
        }
    }
    e = (*r).headers_out.expires;

    if e.is_null() {
        e = bindings::ngx_list_push(&mut (*r).headers_out.headers)
            as *mut bindings::ngx_table_elt_t;
        if e.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }

        (*r).headers_out.expires = e;

        (*e).hash = 1;

        ngx_str_set!(&mut (*e).key, b"Expires\x00");
    }

    len = mem::size_of::<[libc::c_char; 30]>() as u64; // sizeof("Mon, 28 Sep 1970 06:00:00 GMT")
    (*e).value.len = len.wrapping_sub(1);

    ccp = (*r).headers_out.cache_control.elts as *mut *mut bindings::ngx_table_elt_t;

    if ccp.is_null() {
        if ngx_array_macro::ngx_array_init(
            &mut (*r).headers_out.cache_control,
            (*r).pool,
            1,
            mem::size_of::<*mut bindings::ngx_table_elt_t>() as u64,
        ) != bindings::NGX_OK as isize
        {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }
        cc = bindings::ngx_list_push(&mut (*r).headers_out.headers)
            as *mut bindings::ngx_table_elt_t;
        if cc.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }

        (*cc).hash = 1;
        ngx_str_set!(&mut (*cc).key, b"Cache-Control\x00");

        ccp = bindings::ngx_array_push(&mut (*r).headers_out.cache_control)
            as *mut *mut bindings::ngx_table_elt_t;
        if ccp.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }
        *ccp = cc
    } else {
        i = 1;
        while i < (*r).headers_out.cache_control.nelts {
            (**ccp.offset(i as isize)).hash = 0;
            i = i.wrapping_add(1);
        }
        cc = *ccp.offset(0);
    }
    if expires == ngx_http_expires_t::NGX_HTTP_EXPIRES_EPOCH {
        (*e).value.data = b"Thu, 01 Jan 1970 00:00:01 GMT\x00" as *const u8 as *mut u8;
        ngx_str_set!(&mut (*cc).value, b"no-cache\x00");
        return bindings::NGX_OK as bindings::ngx_int_t;
    }
    if expires == ngx_http_expires_t::NGX_HTTP_EXPIRES_MAX {
        (*e).value.data = b"Thu, 31 Dec 2037 23:55:55 GMT\x00" as *const u8 as *mut u8;
        /* 10 years */
        ngx_str_set!(&mut (*cc).value, b"max-age=315360000\x00");
        return bindings::NGX_OK as bindings::ngx_int_t;
    }
    (*e).value.data = bindings::ngx_pnalloc((*r).pool, len) as *mut u8;
    if (*e).value.data.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    if expires_time == 0 && expires != ngx_http_expires_t::NGX_HTTP_EXPIRES_DAILY {
        ngx_string_macro::ngx_memcpy(
            (*e).value.data,
            bindings::ngx_cached_http_time.data,
            bindings::ngx_cached_http_time.len.wrapping_add(1) as usize,
        );
        ngx_str_set!(&mut (*cc).value, b"max-age=0\x00");
        return bindings::NGX_OK as bindings::ngx_int_t;
    }
    now = ngx_time!();
    if expires == ngx_http_expires_t::NGX_HTTP_EXPIRES_DAILY {
        expires_time = bindings::ngx_next_time(expires_time);
        max_age = expires_time - now
    } else if expires == ngx_http_expires_t::NGX_HTTP_EXPIRES_ACCESS
        || (*r).headers_out.last_modified_time == -(1 as libc::c_int) as libc::c_long
    {
        max_age = expires_time;
        expires_time += now
    } else {
        expires_time += (*r).headers_out.last_modified_time;
        max_age = expires_time - now
    }
    bindings::ngx_http_time((*e).value.data, expires_time);
    if (*conf).expires_time < 0 as libc::c_int as libc::c_long
        || max_age < 0 as libc::c_int as libc::c_long
    {
        ngx_str_set!(&mut (*cc).value, b"no-cache\x00");
        return bindings::NGX_OK as bindings::ngx_int_t;
    }
    (*cc).value.data = bindings::ngx_pnalloc(
        (*r).pool,
        (::std::mem::size_of::<[libc::c_char; 9]>() as libc::c_ulong) // sizeof("max-age=")
            .wrapping_add(
                (::std::mem::size_of::<[libc::c_char; 21]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            )
            .wrapping_add(1 as libc::c_int as libc::c_ulong),
    ) as *mut u8;
    if (*cc).value.data.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    (*cc).value.len = bindings::ngx_sprintf(
        (*cc).value.data,
        b"max-age=%T\x00" as *const u8 as *const libc::c_char,
        max_age,
    )
    .offset_from((*cc).value.data) as bindings::size_t;
    return bindings::NGX_OK as bindings::ngx_int_t;
}

unsafe extern "C" fn ngx_http_parse_expires(
    mut value: *mut bindings::ngx_str_t,
    mut expires: *mut ngx_http_expires_t,
    mut expires_time: *mut bindings::time_t,
    mut err: *mut *mut libc::c_char,
) -> bindings::ngx_int_t {
    let mut minus: bindings::ngx_uint_t = 0;
    if *expires != ngx_http_expires_t::NGX_HTTP_EXPIRES_MODIFIED {
        if (*value).len == 5 as libc::c_int as libc::c_ulong
            && ngx_strncmp!((*value).data, b"epoch\0" as *const u8, 5) == 0 as libc::c_int
        {
            *expires = ngx_http_expires_t::NGX_HTTP_EXPIRES_EPOCH;
            return bindings::NGX_OK as bindings::ngx_int_t;
        }
        if (*value).len == 3 as libc::c_int as libc::c_ulong
            && ngx_strncmp!((*value).data, b"max\0" as *const u8, 3) == 0 as libc::c_int
        {
            *expires = ngx_http_expires_t::NGX_HTTP_EXPIRES_MAX;
            return bindings::NGX_OK as bindings::ngx_int_t;
        }
        if (*value).len == 3 as libc::c_int as libc::c_ulong
            && ngx_strncmp!((*value).data, b"off\0" as *const u8, 3) == 0 as libc::c_int
        {
            *expires = ngx_http_expires_t::NGX_HTTP_EXPIRES_OFF;
            return bindings::NGX_OK as bindings::ngx_int_t;
        }
    }
    if (*value).len != 0
        && *(*value).data.offset(0 as libc::c_int as isize) as libc::c_int == '@' as i32
    {
        (*value).data = (*value).data.offset(1);
        (*value).len = (*value).len.wrapping_sub(1);
        minus = 0;
        if *expires == ngx_http_expires_t::NGX_HTTP_EXPIRES_MODIFIED {
            *err = b"daily time cannot be used with \"modified\" parameter\x00" as *const u8
                as *const libc::c_char as *mut libc::c_char;
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }
        *expires = ngx_http_expires_t::NGX_HTTP_EXPIRES_DAILY;
    } else if (*value).len != 0
        && *(*value).data.offset(0 as libc::c_int as isize) as libc::c_int == '+' as i32
    {
        (*value).data = (*value).data.offset(1);
        (*value).len = (*value).len.wrapping_sub(1);
        minus = 0;
    } else if (*value).len != 0
        && *(*value).data.offset(0 as libc::c_int as isize) as libc::c_int == '-' as i32
    {
        (*value).data = (*value).data.offset(1);
        (*value).len = (*value).len.wrapping_sub(1);
        minus = 1;
    } else {
        minus = 0;
    }
    *expires_time = bindings::ngx_parse_time(value, 1) as i64;
    if *expires_time == bindings::NGX_ERROR as bindings::time_t {
        *err = b"invalid value\x00" as *const u8 as *const libc::c_char as *mut i8;
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    if *expires == ngx_http_expires_t::NGX_HTTP_EXPIRES_DAILY
        && *expires_time > (24 * 60 * 60) as libc::c_long
    {
        *err = b"daily time value must be less than 24 hours\x00" as *const u8
            as *const libc::c_char as *mut libc::c_char;
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    if minus != 0 {
        *expires_time = -*expires_time;
    }
    return bindings::NGX_OK as bindings::ngx_int_t;
}

unsafe extern "C" fn ngx_http_add_header(
    mut r: *mut bindings::ngx_http_request_t,
    mut hv: *mut ngx_http_header_val_t,
    mut value: *mut bindings::ngx_str_t,
) -> bindings::ngx_int_t {
    let mut h = 0 as *mut bindings::ngx_table_elt_t;
    if (*value).len != 0 {
        h = bindings::ngx_list_push(&mut (*r).headers_out.headers)
            as *mut bindings::ngx_table_elt_t;
        if h.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }
        (*h).hash = 1;
        (*h).key = (*hv).key;
        (*h).value = *value;
    }
    return bindings::NGX_OK as bindings::ngx_int_t;
}

unsafe extern "C" fn ngx_http_add_multi_header_lines(
    mut r: *mut bindings::ngx_http_request_t,
    mut hv: *mut ngx_http_header_val_t,
    mut value: *mut bindings::ngx_str_t,
) -> bindings::ngx_int_t {
    let mut pa = 0 as *mut bindings::ngx_array_t;
    let mut h = 0 as *mut bindings::ngx_table_elt_t;
    let mut ph = 0 as *mut *mut bindings::ngx_table_elt_t;
    if (*value).len == 0 {
        return bindings::NGX_OK as bindings::ngx_int_t;
    }
    pa = (&mut (*r).headers_out as *mut bindings::ngx_http_headers_out_t as *mut libc::c_char)
        .offset((*hv).offset as isize) as *mut bindings::ngx_array_t;
    if (*pa).elts.is_null() {
        if ngx_array_macro::ngx_array_init(
            pa,
            (*r).pool,
            1,
            mem::size_of::<*mut bindings::ngx_table_elt_t>() as u64,
        ) != bindings::NGX_OK as isize
        {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }
    }
    h = bindings::ngx_list_push(&mut (*r).headers_out.headers) as *mut bindings::ngx_table_elt_t;
    if h.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    (*h).hash = 1;
    (*h).key = (*hv).key;
    (*h).value = *value;
    ph = bindings::ngx_array_push(pa) as *mut *mut bindings::ngx_table_elt_t;
    if ph.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    *ph = h;
    return bindings::NGX_OK as bindings::ngx_int_t;
}

unsafe extern "C" fn ngx_http_set_last_modified(
    mut r: *mut bindings::ngx_http_request_t,
    mut hv: *mut ngx_http_header_val_t,
    mut value: *mut bindings::ngx_str_t,
) -> bindings::ngx_int_t {
    if ngx_http_set_response_header(r, hv, value) != bindings::NGX_OK as isize {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    (*r).headers_out.last_modified_time = if (*value).len != 0 {
        bindings::ngx_parse_http_time((*value).data, (*value).len)
    } else {
        -1
    };
    return bindings::NGX_OK as bindings::ngx_int_t;
}

unsafe extern "C" fn ngx_http_set_response_header(
    mut r: *mut bindings::ngx_http_request_t,
    mut hv: *mut ngx_http_header_val_t,
    mut value: *mut bindings::ngx_str_t,
) -> bindings::ngx_int_t {
    let mut h = 0 as *mut bindings::ngx_table_elt_t;
    let mut old = 0 as *mut *mut bindings::ngx_table_elt_t;
    old = (&mut (*r).headers_out as *mut bindings::ngx_http_headers_out_t as *mut libc::c_char)
        .offset((*hv).offset as isize) as *mut *mut bindings::ngx_table_elt_t;
    if (*value).len == 0 {
        if !(*old).is_null() {
            (**old).hash = 0;
            *old = ptr::null_mut();
        }
        return bindings::NGX_OK as bindings::ngx_int_t;
    }
    if !(*old).is_null() {
        h = *old;
    } else {
        h = bindings::ngx_list_push(&mut (*r).headers_out.headers)
            as *mut bindings::ngx_table_elt_t;
        if h.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }
        *old = h
    }
    (*h).hash = 1;
    (*h).key = (*hv).key;
    (*h).value = *value;
    return bindings::NGX_OK as bindings::ngx_int_t;
}

unsafe extern "C" fn ngx_http_headers_create_conf(
    mut cf: *mut bindings::ngx_conf_t,
) -> *mut libc::c_void {
    let mut conf = 0 as *mut ngx_http_headers_conf_t;
    conf = bindings::ngx_pcalloc((*cf).pool, mem::size_of::<ngx_http_headers_conf_t>() as u64)
        as *mut ngx_http_headers_conf_t;
    if conf.is_null() {
        return ptr::null_mut();
    }
    /*
     * set by ngx_pcalloc():
     *
     *     conf->headers = NULL;
     *     conf->trailers = NULL;
     *     conf->expires_time = 0;
     *     conf->expires_value = NULL;
     */
    (*conf).expires = ngx_http_expires_t::NGX_HTTP_EXPIRES_UNSET; /* cf->args->nelts == 3 */
    return conf as *mut libc::c_void;
}

unsafe extern "C" fn ngx_http_headers_merge_conf(
    mut cf: *mut bindings::ngx_conf_t,
    mut parent: *mut libc::c_void,
    mut child: *mut libc::c_void,
) -> *mut libc::c_char {
    let mut prev = parent as *mut ngx_http_headers_conf_t;
    let mut conf = child as *mut ngx_http_headers_conf_t;
    if (*conf).expires == ngx_http_expires_t::NGX_HTTP_EXPIRES_UNSET {
        (*conf).expires = (*prev).expires;
        (*conf).expires_time = (*prev).expires_time;
        (*conf).expires_value = (*prev).expires_value;
        if (*conf).expires == ngx_http_expires_t::NGX_HTTP_EXPIRES_UNSET {
            (*conf).expires = ngx_http_expires_t::NGX_HTTP_EXPIRES_OFF;
        }
    }
    if (*conf).headers.is_null() {
        (*conf).headers = (*prev).headers;
    }
    if (*conf).trailers.is_null() {
        (*conf).trailers = (*prev).trailers;
    }
    return NGX_CONF_OK!();
}

unsafe extern "C" fn ngx_http_headers_filter_init(
    mut cf: *mut bindings::ngx_conf_t,
) -> bindings::ngx_int_t {
    ngx_http_next_header_filter = bindings::ngx_http_top_header_filter;
    bindings::ngx_http_top_header_filter = Some(ngx_http_headers_filter);

    ngx_http_next_body_filter = bindings::ngx_http_top_body_filter;
    bindings::ngx_http_top_body_filter = Some(ngx_http_trailers_filter);

    return bindings::NGX_OK as bindings::ngx_int_t;
}

unsafe extern "C" fn ngx_http_headers_expires(
    mut cf: *mut bindings::ngx_conf_t,
    mut cmd: *mut bindings::ngx_command_t,
    mut conf: *mut libc::c_void,
) -> *mut libc::c_char {
    let mut hcf = conf as *mut ngx_http_headers_conf_t;
    let mut err = 0 as *mut libc::c_char;
    let mut value = 0 as *mut bindings::ngx_str_t;
    let mut rc: bindings::ngx_int_t = 0;
    let mut n: bindings::ngx_uint_t = 0;
    let mut cv = bindings::ngx_http_complex_value_t {
        value: bindings::ngx_str_t {
            len: 0,
            data: ptr::null_mut(),
        },
        flushes: 0 as *mut bindings::ngx_uint_t,
        lengths: 0 as *mut libc::c_void,
        values: 0 as *mut libc::c_void,
        u: bindings::ngx_http_complex_value_t__bindgen_ty_1 { size: 0 },
    };
    let mut ccv = bindings::ngx_http_compile_complex_value_t {
        cf: 0 as *mut bindings::ngx_conf_t,
        value: 0 as *mut bindings::ngx_str_t,
        complex_value: 0 as *mut bindings::ngx_http_complex_value_t,
        _bitfield_align_1: [0; 0],
        _bitfield_1: bindings::ngx_http_compile_complex_value_t::new_bitfield_1(0, 0, 0),
        __bindgen_padding_0: [0; 7],
    };
    if (*hcf).expires != ngx_http_expires_t::NGX_HTTP_EXPIRES_UNSET {
        return b"is duplicate\x00" as *const u8 as *const libc::c_char as *mut i8;
    }
    value = (*(*cf).args).elts as *mut bindings::ngx_str_t;
    if (*(*cf).args).nelts == 2 {
        (*hcf).expires = ngx_http_expires_t::NGX_HTTP_EXPIRES_ACCESS;
        n = 1;
    } else {
        if ngx_strcmp!((*value.offset(1)).data, b"modified\x00" as *const u8) != 0 as libc::c_int {
            return b"invalid value\x00" as *const u8 as *const libc::c_char as *mut libc::c_char;
        }
        (*hcf).expires = ngx_http_expires_t::NGX_HTTP_EXPIRES_MODIFIED;
        n = 2;
    }

    ngx_memzero!(
        &mut ccv,
        mem::size_of::<bindings::ngx_http_compile_complex_value_t>()
    );

    ccv.cf = cf;
    ccv.value = &mut *value.offset(n as isize) as *mut bindings::ngx_str_t;
    ccv.complex_value = &mut cv;
    if bindings::ngx_http_compile_complex_value(&mut ccv) != bindings::NGX_OK as isize {
        return NGX_CONF_ERROR!();
    }
    if !cv.lengths.is_null() {
        (*hcf).expires_value = bindings::ngx_palloc(
            (*cf).pool,
            mem::size_of::<bindings::ngx_http_complex_value_t>() as libc::c_ulong,
        ) as *mut bindings::ngx_http_complex_value_t;
        if (*hcf).expires_value.is_null() {
            return NGX_CONF_ERROR!();
        }
        *(*hcf).expires_value = cv;
        return NGX_CONF_OK!();
    }
    rc = ngx_http_parse_expires(
        &mut *value.offset(n as isize),
        &mut (*hcf).expires,
        &mut (*hcf).expires_time,
        &mut err,
    );
    if rc != bindings::NGX_OK as isize {
        return err;
    }
    return NGX_CONF_OK!();
}

unsafe extern "C" fn ngx_http_headers_add(
    mut cf: *mut bindings::ngx_conf_t,
    mut cmd: *mut bindings::ngx_command_t,
    mut conf: *mut libc::c_void,
) -> *mut libc::c_char {
    let mut hcf = conf as *mut ngx_http_headers_conf_t;
    let mut value = 0 as *mut bindings::ngx_str_t;
    let mut i: bindings::ngx_uint_t = 0;
    let mut headers = 0 as *mut *mut bindings::ngx_array_t;
    let mut hv = 0 as *mut ngx_http_header_val_t;
    let mut set = 0 as *mut ngx_http_set_header_t;
    let mut ccv = bindings::ngx_http_compile_complex_value_t {
        cf: 0 as *mut bindings::ngx_conf_t,
        value: 0 as *mut bindings::ngx_str_t,
        complex_value: 0 as *mut bindings::ngx_http_complex_value_t,
        _bitfield_align_1: [0; 0],
        _bitfield_1: bindings::ngx_http_compile_complex_value_t::new_bitfield_1(0, 0, 0),
        __bindgen_padding_0: [0; 7],
    };
    value = (*(*cf).args).elts as *mut bindings::ngx_str_t;
    headers = (hcf as *mut libc::c_char).offset((*cmd).offset as isize)
        as *mut *mut bindings::ngx_array_t;
    if (*headers).is_null() {
        *headers = bindings::ngx_array_create(
            (*cf).pool,
            1,
            mem::size_of::<ngx_http_header_val_t>() as libc::c_ulong,
        );
        if (*headers).is_null() {
            return NGX_CONF_ERROR!();
        }
    }
    hv = bindings::ngx_array_push(*headers) as *mut ngx_http_header_val_t;
    if hv.is_null() {
        return NGX_CONF_ERROR!();
    }
    (*hv).key = *value.offset(1 as libc::c_int as isize);
    (*hv).handler = None;
    (*hv).offset = 0;
    (*hv).always = 0;
    if headers == &mut (*hcf).headers as *mut *mut bindings::ngx_array_t {
        (*hv).handler = Some(ngx_http_add_header);
        set = ngx_http_set_headers.as_mut_ptr();
        i = 0;
        while (*set.offset(i as isize)).name.len != 0 {
            if bindings::ngx_strcasecmp(
                (*value.offset(1 as libc::c_int as isize)).data,
                (*set.offset(i as isize)).name.data,
            ) != 0
            {
                i = i.wrapping_add(1)
            } else {
                (*hv).offset = (*set.offset(i as isize)).offset;
                (*hv).handler = (*set.offset(i as isize)).handler;
                break;
            }
        }
    }
    if !((*value.offset(2)).len == 0) {
        ngx_memzero!(
            &mut ccv,
            mem::size_of::<bindings::ngx_http_compile_complex_value_t>()
        );

        ccv.cf = cf;
        ccv.value = &mut *value.offset(2 as libc::c_int as isize) as *mut bindings::ngx_str_t;
        ccv.complex_value = &mut (*hv).value;
        if bindings::ngx_http_compile_complex_value(&mut ccv) != bindings::NGX_OK as isize {
            return NGX_CONF_ERROR!();
        }
    } else {
        ngx_memzero!(
            &mut (*hv).value,
            mem::size_of::<bindings::ngx_http_complex_value_t>()
        );
    }
    if (*(*cf).args).nelts == 3 {
        return NGX_CONF_OK!();
    }
    if ngx_strcmp!((*value.offset(3)).data, b"always\x00" as *const u8) != 0 as libc::c_int {
        bindings::ngx_conf_log_error(
            bindings::NGX_LOG_EMERG as bindings::ngx_uint_t,
            cf,
            0,
            b"invalid parameter \"%V\"\x00" as *const u8 as *const libc::c_char,
            &mut *value.offset(3 as libc::c_int as isize) as *mut bindings::ngx_str_t,
        );
        return NGX_CONF_ERROR!();
    }
    (*hv).always = 1;
    return NGX_CONF_OK!();
}
unsafe extern "C" fn run_static_initializers() {
    ngx_http_set_headers = [
        {
            let init = ngx_http_set_header_t {
                name: ngx_string!("Cache-Control\0"),
                offset: offset_of!(bindings::ngx_http_headers_out_t, cache_control),
                handler: Some(ngx_http_add_multi_header_lines),
            };
            init
        },
        {
            let init = ngx_http_set_header_t {
                name: ngx_string!("Link\0"),
                offset: offset_of!(bindings::ngx_http_headers_out_t, link),
                handler: Some(ngx_http_add_multi_header_lines),
            };
            init
        },
        {
            let init = ngx_http_set_header_t {
                name: ngx_string!("Last-Modified\0"),
                offset: offset_of!(bindings::ngx_http_headers_out_t, last_modified),
                handler: Some(ngx_http_set_last_modified),
            };
            init
        },
        {
            let init = ngx_http_set_header_t {
                name: ngx_string!("ETag\0"),
                offset: offset_of!(bindings::ngx_http_headers_out_t, etag),
                handler: Some(ngx_http_set_response_header),
            };
            init
        },
        {
            let init = ngx_http_set_header_t {
                name: {
                    let init = bindings::ngx_str_t {
                        len: 0,
                        data: ptr::null_mut(),
                    };
                    init
                },
                offset: 0,
                handler: None,
            };
            init
        },
    ];
    ngx_http_headers_filter_commands = [
        {
            let init = bindings::ngx_command_t {
                name: ngx_string!("expires\0"),
                type_: (bindings::NGX_HTTP_MAIN_CONF
                    | bindings::NGX_HTTP_SRV_CONF
                    | bindings::NGX_HTTP_LOC_CONF
                    | bindings::NGX_HTTP_LIF_CONF
                    | bindings::NGX_CONF_TAKE12) as bindings::ngx_uint_t,
                set: Some(ngx_http_headers_expires),
                conf: NGX_HTTP_LOC_CONF_OFFSET!(),
                offset: 0,
                post: ptr::null_mut(),
            };
            init
        },
        {
            let init = bindings::ngx_command_t {
                name: ngx_string!("add_header\0"),
                type_: (bindings::NGX_HTTP_MAIN_CONF
                    | bindings::NGX_HTTP_SRV_CONF
                    | bindings::NGX_HTTP_LOC_CONF
                    | bindings::NGX_HTTP_LIF_CONF
                    | bindings::NGX_CONF_TAKE23) as bindings::ngx_uint_t,
                set: Some(ngx_http_headers_add),
                conf: NGX_HTTP_LOC_CONF_OFFSET!(),
                offset: offset_of!(ngx_http_headers_conf_t, headers),
                post: ptr::null_mut(),
            };
            init
        },
        {
            let init = bindings::ngx_command_t {
                name: ngx_string!("add_trailer\0"),
                type_: (bindings::NGX_HTTP_MAIN_CONF
                    | bindings::NGX_HTTP_SRV_CONF
                    | bindings::NGX_HTTP_LOC_CONF
                    | bindings::NGX_HTTP_LIF_CONF
                    | bindings::NGX_CONF_TAKE23) as bindings::ngx_uint_t,
                set: Some(ngx_http_headers_add),
                conf: NGX_HTTP_LOC_CONF_OFFSET!(),
                offset: offset_of!(ngx_http_headers_conf_t, trailers),
                post: ptr::null_mut(),
            };
            init
        },
        {
            let init = bindings::ngx_command_t {
                name: {
                    let init = bindings::ngx_str_t {
                        len: 0,
                        data: ptr::null_mut(),
                    };
                    init
                },
                type_: 0,
                set: None,
                conf: 0,
                offset: 0,
                post: ptr::null_mut(),
            };
            init
        },
    ]
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
