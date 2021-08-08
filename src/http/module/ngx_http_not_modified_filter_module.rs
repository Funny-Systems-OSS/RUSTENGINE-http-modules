use crate::bindings;
use crate::core::ngx_module_macro;
use std::ptr;

static mut ngx_http_not_modified_filter_module_ctx: bindings::ngx_http_module_t = unsafe {
    {
        let init = bindings::ngx_http_module_t {
            preconfiguration: None,
            postconfiguration: Some(ngx_http_not_modified_filter_init),
            create_main_conf: None,
            init_main_conf: None,
            create_srv_conf: None,
            merge_srv_conf: None,
            create_loc_conf: None,
            merge_loc_conf: None,
        };
        init
    }
};
#[no_mangle]
pub static mut ngx_http_not_modified_filter_module: bindings::ngx_module_t = unsafe {
    {
        let init = bindings::ngx_module_t {
            ctx_index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as usize,
            index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as usize,
            name: ptr::null_mut(),
            spare0: 0,
            spare1: 0,
            version: bindings::nginx_version as bindings::ngx_uint_t,
            signature: ngx_module_macro::NGX_MODULE_SIGNATURE as *const u8 as *const i8,
            ctx: &ngx_http_not_modified_filter_module_ctx as *const bindings::ngx_http_module_t
                as *mut bindings::ngx_http_module_t as *mut libc::c_void,
            commands: ptr::null_mut(),
            type_: bindings::NGX_HTTP_MODULE as usize,
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

unsafe extern "C" fn ngx_http_not_modified_header_filter(
    mut r: *mut bindings::ngx_http_request_t,
) -> bindings::ngx_int_t {
    if (*r).headers_out.status != bindings::NGX_HTTP_OK as usize
        || r != (*r).main
        || (*r).disable_not_modified() != 0
    {
        return ngx_http_next_header_filter.expect("non-null function pointer")(r);
    }
    if !(*r).headers_in.if_unmodified_since.is_null() && ngx_http_test_if_unmodified(r) == 0 {
        return bindings::ngx_http_filter_finalize_request(
            r,
            ptr::null_mut(),
            bindings::NGX_HTTP_PRECONDITION_FAILED as bindings::ngx_int_t,
        );
    }
    if !(*r).headers_in.if_match.is_null()
        && ngx_http_test_if_match(r, (*r).headers_in.if_match, 0 as bindings::ngx_uint_t) == 0
    {
        return bindings::ngx_http_filter_finalize_request(
            r,
            ptr::null_mut(),
            bindings::NGX_HTTP_PRECONDITION_FAILED as bindings::ngx_int_t,
        );
    }
    if !(*r).headers_in.if_modified_since.is_null() || !(*r).headers_in.if_none_match.is_null() {
        if !(*r).headers_in.if_modified_since.is_null() && ngx_http_test_if_modified(r) != 0 {
            return ngx_http_next_header_filter.expect("non-null function pointer")(r);
        }
        if !(*r).headers_in.if_none_match.is_null()
            && ngx_http_test_if_match(r, (*r).headers_in.if_none_match, 1 as bindings::ngx_uint_t)
                == 0
        {
            return ngx_http_next_header_filter.expect("non-null function pointer")(r);
        }
        /* not modified */
        (*r).headers_out.status = bindings::NGX_HTTP_NOT_MODIFIED as bindings::ngx_uint_t;
        (*r).headers_out.status_line.len = 0 as bindings::size_t;
        (*r).headers_out.content_type.len = 0 as bindings::size_t;
        ngx_http_clear_content_length!(r);
        ngx_http_clear_accept_ranges!(r);

        if !(*r).headers_out.content_encoding.is_null() {
            (*(*r).headers_out.content_encoding).hash = 0 as bindings::ngx_uint_t;
            (*r).headers_out.content_encoding = ptr::null_mut()
        }
        return ngx_http_next_header_filter.expect("non-null function pointer")(r);
    }
    return ngx_http_next_header_filter.expect("non-null function pointer")(r);
}

unsafe extern "C" fn ngx_http_test_if_unmodified(
    mut r: *mut bindings::ngx_http_request_t,
) -> bindings::ngx_uint_t {
    let mut iums: bindings::time_t = 0;
    if (*r).headers_out.last_modified_time == -(1) as bindings::time_t {
        return 0 as bindings::ngx_uint_t;
    }
    iums = bindings::ngx_parse_http_time(
        (*(*r).headers_in.if_unmodified_since).value.data,
        (*(*r).headers_in.if_unmodified_since).value.len,
    );

    ngx_log_debug!(
        bindings::NGX_LOG_DEBUG,
        (*(*r).connection).log,
        0,
        b"http iums:%T lm:%T\x00" as *const u8 as *const i8,
        iums,
        (*r).headers_out.last_modified_time
    );

    if iums >= (*r).headers_out.last_modified_time {
        return 1 as bindings::ngx_uint_t;
    }
    return 0 as bindings::ngx_uint_t;
}

unsafe extern "C" fn ngx_http_test_if_modified(
    mut r: *mut bindings::ngx_http_request_t,
) -> bindings::ngx_uint_t {
    let mut ims: bindings::time_t = 0;
    let mut clcf = 0 as *mut bindings::ngx_http_core_loc_conf_t;
    if (*r).headers_out.last_modified_time == -(1) as bindings::time_t {
        return 1 as bindings::ngx_uint_t;
    }
    clcf = *ngx_http_get_module_loc_conf!(r, bindings::ngx_http_core_module)
        as *mut bindings::ngx_http_core_loc_conf_t;
    if (*clcf).if_modified_since == bindings::NGX_HTTP_IMS_OFF as usize {
        return 1 as bindings::ngx_uint_t;
    }
    ims = bindings::ngx_parse_http_time(
        (*(*r).headers_in.if_modified_since).value.data,
        (*(*r).headers_in.if_modified_since).value.len,
    );
    ngx_log_debug!(
        bindings::NGX_LOG_DEBUG as bindings::ngx_uint_t,
        (*(*r).connection).log,
        0,
        b"http ims:%T lm:%T\x00" as *const u8 as *const i8,
        ims,
        (*r).headers_out.last_modified_time
    );
    if ims == (*r).headers_out.last_modified_time {
        return 0 as bindings::ngx_uint_t;
    }
    if (*clcf).if_modified_since == bindings::NGX_HTTP_IMS_EXACT as usize
        || ims < (*r).headers_out.last_modified_time
    {
        return 1 as bindings::ngx_uint_t;
    }
    return 0 as bindings::ngx_uint_t;
}

unsafe extern "C" fn ngx_http_test_if_match(
    mut r: *mut bindings::ngx_http_request_t,
    mut header: *mut bindings::ngx_table_elt_t,
    mut weak: bindings::ngx_uint_t,
) -> bindings::ngx_uint_t {
    let mut start = 0 as *mut bindings::u_char;
    let mut end = 0 as *mut bindings::u_char;
    let mut ch: bindings::u_char = 0;
    let mut etag = bindings::ngx_str_t {
        len: 0,
        data: 0 as *mut bindings::u_char,
    };
    let mut list = 0 as *mut bindings::ngx_str_t;
    list = &mut (*header).value;
    if (*list).len == 1 && *(*list).data.offset(0 as isize) as i32 == '*' as i32 {
        return 1 as bindings::ngx_uint_t;
    }
    if (*r).headers_out.etag.is_null() {
        return 0 as bindings::ngx_uint_t;
    }
    etag = (*(*r).headers_out.etag).value;

    ngx_log_debug!(
        bindings::NGX_LOG_DEBUG as bindings::ngx_uint_t,
        (*(*r).connection).log,
        0,
        b"http im:\"%V\" etag:%V\x00" as *const u8 as *const libc::c_char,
        list,
        &mut etag as *mut bindings::ngx_str_t
    );

    if weak != 0
        && etag.len > 2
        && *etag.data.offset(0 as isize) as i32 == 'W' as i32
        && *etag.data.offset(1 as isize) as i32 == '/' as i32
    {
        etag.len = (etag.len).wrapping_sub(2) as bindings::size_t;
        etag.data = etag.data.offset(2 as isize)
    }
    start = (*list).data;
    end = (*list).data.offset((*list).len as isize);
    while start < end {
        if weak != 0
            && end.offset_from(start) > 2
            && *start.offset(0) as i32 == 'W' as i32
            && *start.offset(1) as i32 == '/' as i32
        {
            start = start.offset(2 as isize)
        }
        if etag.len > end.offset_from(start) as libc::c_long as bindings::size_t {
            return 0;
        }

        if !(ngx_strncmp!(start, etag.data, etag.len as usize) != 0) {
            start = start.offset(etag.len as isize);
            while start < end {
                ch = *start;
                if !(ch as i32 == ' ' as i32 || ch as i32 == '\t' as i32) {
                    break;
                }
                start = start.offset(1)
            }
            if start == end || *start as i32 == ',' as i32 {
                return 1;
            }
        }
        while start < end && *start as i32 != ',' as i32 {
            start = start.offset(1)
        }
        while start < end {
            ch = *start;
            if !(ch as i32 == ' ' as i32 || ch as i32 == '\t' as i32 || ch as i32 == ',' as i32) {
                break;
            }
            start = start.offset(1)
        }
    }
    return 0 as bindings::ngx_uint_t;
}

unsafe extern "C" fn ngx_http_not_modified_filter_init(
    _: *mut bindings::ngx_conf_t,
) -> bindings::ngx_int_t {
    ngx_http_next_header_filter = bindings::ngx_http_top_header_filter;
    bindings::ngx_http_top_header_filter = Some(ngx_http_not_modified_header_filter);
    return bindings::NGX_OK as bindings::ngx_int_t;
}
