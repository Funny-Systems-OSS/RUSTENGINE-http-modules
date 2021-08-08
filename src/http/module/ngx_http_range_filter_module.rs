use crate::bindings;
use crate::core::ngx_array_macro;
use crate::core::ngx_core_macro;
use crate::core::ngx_module_macro;
use crate::core::ngx_string_macro;
use crate::os::unix::ngx_atomic_macro;
use std::mem;
use std::ptr;
/*
 * the single part format:
 *
 * "HTTP/1.0 206 Partial Content" CRLF
 * ... header ...
 * "Content-Type: image/jpeg" CRLF
 * "Content-Length: SIZE" CRLF
 * "Content-Range: bytes START-END/SIZE" CRLF
 * CRLF
 * ... data ...
 *
 *
 * the multipart format:
 *
 * "HTTP/1.0 206 Partial Content" CRLF
 * ... header ...
 * "Content-Type: multipart/byteranges; boundary=0123456789" CRLF
 * CRLF
 * CRLF
 * "--0123456789" CRLF
 * "Content-Type: image/jpeg" CRLF
 * "Content-Range: bytes START0-END0/SIZE" CRLF
 * CRLF
 * ... data ...
 * CRLF
 * "--0123456789" CRLF
 * "Content-Type: image/jpeg" CRLF
 * "Content-Range: bytes START1-END1/SIZE" CRLF
 * CRLF
 * ... data ...
 * CRLF
 * "--0123456789--" CRLF
 */

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngx_http_range_t {
    pub start: bindings::off_t,
    pub end: bindings::off_t,
    pub content_range: bindings::ngx_str_t,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngx_http_range_filter_ctx_t {
    pub offset: bindings::off_t,
    pub boundary_header: bindings::ngx_str_t,
    pub ranges: bindings::ngx_array_t,
}
static mut ngx_http_range_header_filter_module_ctx: bindings::ngx_http_module_t = unsafe {
    {
        let mut init = bindings::ngx_http_module_t {
            preconfiguration: None,
            postconfiguration: Some(ngx_http_range_header_filter_init),
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
pub static mut ngx_http_range_header_filter_module: bindings::ngx_module_t = unsafe {
    {
        let mut init = bindings::ngx_module_t {
            ctx_index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as bindings::ngx_uint_t,
            index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as bindings::ngx_uint_t,
            name: ptr::null_mut(),
            spare0: 0,
            spare1: 0,
            version: bindings::nginx_version as bindings::ngx_uint_t,
            signature: ngx_module_macro::NGX_MODULE_SIGNATURE as *const u8 as *const libc::c_char,
            ctx: &ngx_http_range_header_filter_module_ctx as *const bindings::ngx_http_module_t
                as *mut bindings::ngx_http_module_t as *mut libc::c_void,
            commands: ptr::null_mut(),
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

static mut ngx_http_range_body_filter_module_ctx: bindings::ngx_http_module_t = unsafe {
    {
        let mut init = bindings::ngx_http_module_t {
            preconfiguration: None,
            postconfiguration: Some(ngx_http_range_body_filter_init),
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
pub static mut ngx_http_range_body_filter_module: bindings::ngx_module_t = unsafe {
    {
        let mut init = bindings::ngx_module_t {
            ctx_index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as bindings::ngx_uint_t,
            index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as bindings::ngx_uint_t,
            name: ptr::null_mut(),
            spare0: 0,
            spare1: 0,
            version: bindings::nginx_version as bindings::ngx_uint_t,
            signature: ngx_module_macro::NGX_MODULE_SIGNATURE as *const u8 as *const libc::c_char,
            ctx: &ngx_http_range_body_filter_module_ctx as *const bindings::ngx_http_module_t
                as *mut bindings::ngx_http_module_t as *mut libc::c_void,
            commands: ptr::null_mut(),
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

unsafe extern "C" fn ngx_http_range_header_filter(
    mut r: *mut bindings::ngx_http_request_t,
) -> bindings::ngx_int_t {
    let mut current_block: u64;
    let mut if_range_time: bindings::time_t = 0;
    let mut if_range = 0 as *mut bindings::ngx_str_t;
    let mut etag = 0 as *mut bindings::ngx_str_t;
    let mut ranges: bindings::ngx_uint_t = 0;
    let mut clcf = 0 as *mut bindings::ngx_http_core_loc_conf_t;
    let mut ctx = 0 as *mut ngx_http_range_filter_ctx_t;

    if (*r).http_version < bindings::NGX_HTTP_VERSION_10 as usize
        || (*r).headers_out.status != bindings::NGX_HTTP_OK as usize
        || r != (*r).main && (*r).subrequest_ranges() == 0
        || (*r).headers_out.content_length_n == -1
        || (*r).allow_ranges() == 0
    {
        return ngx_http_next_header_filter.expect("non-null function pointer")(r);
    }
    clcf = *ngx_http_get_module_loc_conf!(r, bindings::ngx_http_core_module)
        as *mut bindings::ngx_http_core_loc_conf_t;

    if (*clcf).max_ranges == 0 {
        return ngx_http_next_header_filter.expect("non-null function pointer")(r);
    }

    'next_filter: loop {
        'parse: loop {
            if (*r).headers_in.range.is_null()
                || (*(*r).headers_in.range).value.len < 7
                || bindings::ngx_strncasecmp(
                    (*(*r).headers_in.range).value.data,
                    b"bytes=\x00" as *const u8 as *const libc::c_char as *mut bindings::u_char,
                    6,
                ) != 0
            {
                break 'next_filter; // goto next_filter;
            }

            if !(*r).headers_in.if_range.is_null() {
                if_range = &mut (*(*r).headers_in.if_range).value;

                if (*if_range).len >= 2
                    && *(*if_range)
                        .data
                        .offset((*if_range).len.wrapping_sub(1) as isize)
                        as i32
                        == '\"' as i32
                {
                    if (*r).headers_out.etag.is_null() {
                        break 'next_filter; // goto next_filter;
                    }
                    etag = &mut (*(*r).headers_out.etag).value;
                    ngx_log_debug!(
                        bindings::NGX_LOG_DEBUG_HTTP as bindings::ngx_uint_t,
                        (*(*r).connection).log,
                        0,
                        b"http ir:%V etag:%V\x00" as *const u8 as *const libc::c_char,
                        if_range,
                        etag
                    );
                    if (*if_range).len != (*etag).len
                        || ngx_strncmp!((*if_range).data, (*etag).data, (*etag).len) != 0
                    {
                        break 'next_filter; // goto next_filter;
                    }
                    break 'parse; // goto parse;
                }
                if (*r).headers_out.last_modified_time == -1 as bindings::time_t {
                    break 'next_filter; // goto next_filter;
                }
                if_range_time = bindings::ngx_parse_http_time((*if_range).data, (*if_range).len);
                ngx_log_debug!(
                    bindings::NGX_LOG_DEBUG_HTTP as bindings::ngx_uint_t,
                    (*(*r).connection).log,
                    0,
                    b"http ir:%T lm:%T\x00" as *const u8 as *const libc::c_char,
                    if_range_time,
                    (*r).headers_out.last_modified_time
                );
                if if_range_time != (*r).headers_out.last_modified_time {
                    break 'next_filter; // goto next_filter;
                }
            }
            break;
        }
        ctx = bindings::ngx_pcalloc(
            (*r).pool,
            mem::size_of::<ngx_http_range_filter_ctx_t>() as libc::c_ulong,
        ) as *mut ngx_http_range_filter_ctx_t;
        if ctx.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }
        (*ctx).offset = (*r).headers_out.content_offset;
        ranges = if (*r).single_range() as libc::c_int != 0 {
            1
        } else {
            (*clcf).max_ranges
        };
        let http_range_parse_result: i32 = ngx_http_range_parse(r, ctx, ranges) as i32;
        match http_range_parse_result {
            bindings::NGX_OK => {
                ngx_http_set_ctx!(
                    r,
                    ctx as *mut libc::c_void,
                    ngx_http_range_body_filter_module
                );

                (*r).headers_out.status =
                    bindings::NGX_HTTP_PARTIAL_CONTENT as bindings::ngx_uint_t;
                (*r).headers_out.status_line.len = 0;

                if (*ctx).ranges.nelts == 1 {
                    return ngx_http_range_singlepart_header(r, ctx);
                }
                return ngx_http_range_multipart_header(r, ctx);
            }
            bindings::NGX_HTTP_RANGE_NOT_SATISFIABLE => return ngx_http_range_not_satisfiable(r),
            bindings::NGX_ERROR => return bindings::NGX_ERROR as bindings::ngx_int_t,
            _ => {}
        }
        break;
    }
    (*r).headers_out.accept_ranges =
        bindings::ngx_list_push(&mut (*r).headers_out.headers) as *mut bindings::ngx_table_elt_t;
    if (*r).headers_out.accept_ranges.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    (*(*r).headers_out.accept_ranges).hash = 1;
    ngx_str_set!(
        &mut (*(*r).headers_out.accept_ranges).key,
        b"Accept-Ranges\0"
    );
    ngx_str_set!(&mut (*(*r).headers_out.accept_ranges).value, b"bytes\0");
    return ngx_http_next_header_filter.expect("non-null function pointer")(r);
}

unsafe extern "C" fn ngx_http_range_parse(
    mut r: *mut bindings::ngx_http_request_t,
    mut ctx: *mut ngx_http_range_filter_ctx_t,
    mut ranges: bindings::ngx_uint_t,
) -> bindings::ngx_int_t {
    let mut p = 0 as *mut bindings::u_char;
    let mut start: bindings::off_t = 0;
    let mut end: bindings::off_t = 0;
    let mut size: bindings::off_t = 0;
    let mut content_length: bindings::off_t = 0;
    let mut cutoff: bindings::off_t = 0;
    let mut cutlim: bindings::off_t = 0;
    let mut suffix: bindings::ngx_uint_t = 0;
    let mut range: *mut ngx_http_range_t = ptr::null_mut();
    let mut mctx: *mut ngx_http_range_filter_ctx_t = ptr::null_mut();

    if r != (*r).main {
        mctx = *ngx_http_get_module_ctx!((*r).main, ngx_http_range_body_filter_module)
            as *mut ngx_http_range_filter_ctx_t;
        if !mctx.is_null() {
            (*ctx).ranges = (*mctx).ranges;
            return bindings::NGX_OK as bindings::ngx_int_t;
        }
    }
    if ngx_array_macro::ngx_array_init(
        &mut (*ctx).ranges,
        (*r).pool,
        1,
        mem::size_of::<ngx_http_range_t>() as u64,
    ) != bindings::NGX_OK as isize
    {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }

    p = (*(*r).headers_in.range).value.data.offset(6);
    size = 0;
    content_length = (*r).headers_out.content_length_n;

    cutoff = (bindings::NGX_MAX_OFF_T_VALUE / 10) as bindings::off_t;
    cutlim = (bindings::NGX_MAX_OFF_T_VALUE % 10) as bindings::off_t;
    let mut current_block_84: u64;
    let mut found: bool = false;
    loop {
        start = 0;
        end = 0;
        suffix = 0;

        while *p as i32 == ' ' as i32 {
            p = p.offset(1)
        }

        if *p as i32 != '-' as i32 {
            if !(*p).is_ascii_digit() {
                // if (*p as i32) < '0' as i32 || *p as i32 > '9' as i32 {
                return bindings::NGX_HTTP_RANGE_NOT_SATISFIABLE as bindings::ngx_int_t;
            }
            while (*p).is_ascii_digit() {
                // while *p as libc::c_int >= '0' as i32 && *p as libc::c_int <= '9' as i32 {
                if start >= cutoff
                    && (start > cutoff || (*p as i32 - '0' as i32) as libc::c_long > cutlim)
                {
                    return bindings::NGX_HTTP_RANGE_NOT_SATISFIABLE as bindings::ngx_int_t;
                }

                start = start * 10 + (*p as i32 - '0' as i32) as i64;
                p = p.offset(1);
            }

            while *p as libc::c_int == ' ' as i32 {
                p = p.offset(1);
            }

            if *p as libc::c_int != '-' as i32 {
                return bindings::NGX_HTTP_RANGE_NOT_SATISFIABLE as bindings::ngx_int_t;
            }
            p = p.offset(1);

            while *p as i32 == ' ' as i32 {
                p = p.offset(1);
            }

            if *p as libc::c_int == ',' as i32 || *p as libc::c_int == '\u{0}' as i32 {
                end = content_length;
                // goto found;
                found = true;
            } else {
                found = false;
            }
        } else {
            suffix = 1;
            p = p.offset(1);
            found = false;
        }
        match found {
            false => {
                if !(*p).is_ascii_digit() {
                    // if (*p as libc::c_int) < '0' as i32 || *p as libc::c_int > '9' as i32 {
                    return bindings::NGX_HTTP_RANGE_NOT_SATISFIABLE as bindings::ngx_int_t;
                }
                while (*p).is_ascii_digit() {
                    // while *p as libc::c_int >= '0' as i32 && *p as libc::c_int <= '9' as i32 {
                    if end >= cutoff
                        && (end > cutoff || (*p as i32 - '0' as i32) as libc::c_long > cutlim)
                    {
                        return bindings::NGX_HTTP_RANGE_NOT_SATISFIABLE as bindings::ngx_int_t;
                    }

                    end = end * 10 + (*p as i32 - '0' as i32) as libc::c_long;
                    p = p.offset(1);
                }

                while *p as i32 == ' ' as i32 {
                    p = p.offset(1)
                }

                if *p as i32 != ',' as i32 && *p as i32 != '\u{0}' as i32 {
                    return bindings::NGX_HTTP_RANGE_NOT_SATISFIABLE as bindings::ngx_int_t;
                }

                if suffix != 0 {
                    start = if end < content_length {
                        (content_length) - end
                    } else {
                        0
                    };
                    end = content_length - 1;
                }
                if end >= content_length {
                    end = content_length;
                } else {
                    end += 1;
                }
            }
            _ => {}
        }
        if start < end {
            range = bindings::ngx_array_push(&mut (*ctx).ranges) as *mut ngx_http_range_t;
            if range.is_null() {
                return bindings::NGX_ERROR as bindings::ngx_int_t;
            }

            (*range).start = start;
            (*range).end = end;

            if size as libc::c_longlong
                > bindings::NGX_MAX_OFF_T_VALUE - (end - start) as libc::c_longlong
            {
                return bindings::NGX_HTTP_RANGE_NOT_SATISFIABLE as bindings::ngx_int_t;
            }

            size += end - start;

            if range.is_null() {
                return bindings::NGX_DECLINED as bindings::ngx_int_t;
            }
            ranges = ranges.wrapping_sub(1);
        } else if start == 0 {
            return bindings::NGX_DECLINED as bindings::ngx_int_t;
        }
        if *p as i32 != ',' as i32 {
            break;
        }
        p = p.offset(1);
    }
    if (*ctx).ranges.nelts == 0 {
        return bindings::NGX_HTTP_RANGE_NOT_SATISFIABLE as bindings::ngx_int_t;
    }
    if size > content_length {
        return bindings::NGX_DECLINED as bindings::ngx_int_t;
    }
    return bindings::NGX_OK as bindings::ngx_int_t;
}

unsafe extern "C" fn ngx_http_range_singlepart_header(
    mut r: *mut bindings::ngx_http_request_t,
    mut ctx: *mut ngx_http_range_filter_ctx_t,
) -> bindings::ngx_int_t {
    let mut content_range: *mut bindings::ngx_table_elt_t = ptr::null_mut();
    let mut range: *mut ngx_http_range_t = ptr::null_mut();

    if r != (*r).main {
        return ngx_http_next_header_filter.expect("non-null function pointer")(r);
    }

    content_range =
        bindings::ngx_list_push(&mut (*r).headers_out.headers) as *mut bindings::ngx_table_elt_t;
    if content_range.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }

    (*r).headers_out.content_range = content_range;

    (*content_range).hash = 1;
    ngx_str_set!(&mut (*content_range).key, "Content-Range");

    (*content_range).value.data = bindings::ngx_pnalloc(
        (*r).pool,
        (mem::size_of::<[libc::c_char; 9]>() as libc::c_ulong) // sizeof("bytes -/")
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (3 as libc::c_int as libc::c_ulong).wrapping_mul(
                    (mem::size_of::<[libc::c_char; 21]>() as libc::c_ulong) // sizeof("-9223372036854775808")
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                ),
            ),
    ) as *mut bindings::u_char;
    if (*content_range).value.data.is_null() {
        (*content_range).hash = 0;
        (*r).headers_out.content_range = ptr::null_mut();
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }

    /* "Content-Range: bytes SSSS-EEEE/TTTT" header */
    range = (*ctx).ranges.elts as *mut ngx_http_range_t;

    (*content_range).value.len = bindings::ngx_sprintf(
        (*content_range).value.data,
        b"bytes %O-%O/%O\x00" as *const u8 as *const libc::c_char,
        (*range).start,
        (*range).end - 1 as libc::c_int as libc::c_long,
        (*r).headers_out.content_length_n,
    )
    .offset_from((*content_range).value.data) as libc::c_long
        as bindings::size_t;

    (*r).headers_out.content_length_n = (*range).end - (*range).start;
    (*r).headers_out.content_offset = (*range).start;

    if !(*r).headers_out.content_length.is_null() {
        (*(*r).headers_out.content_length).hash = 0;
        (*r).headers_out.content_length = ptr::null_mut();
    }

    return ngx_http_next_header_filter.expect("non-null function pointer")(r);
}

unsafe extern "C" fn ngx_http_range_multipart_header(
    mut r: *mut bindings::ngx_http_request_t,
    mut ctx: *mut ngx_http_range_filter_ctx_t,
) -> bindings::ngx_int_t {
    let mut len: bindings::off_t = 0;
    let mut size: bindings::size_t = 0;
    let mut i: bindings::ngx_uint_t = 0;
    let mut range: *mut ngx_http_range_t = ptr::null_mut();
    let mut boundary: bindings::ngx_atomic_uint_t = 0;

    size = (mem::size_of::<[libc::c_char; 5]>() as libc::c_ulong) // sizeof(CRLF "--")
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        .wrapping_add(
            (mem::size_of::<[libc::c_char; 21]>() as libc::c_ulong) // sizeof("-9223372036854775808")
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        )
        .wrapping_add(::std::mem::size_of::<[libc::c_char; 17]>() as libc::c_ulong) // sizeof(CRLF "Content-Type: ") - 1
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        .wrapping_add((*r).headers_out.content_type.len)
        .wrapping_add(::std::mem::size_of::<[libc::c_char; 24]>() as libc::c_ulong) // sizeof(CRLF "Content-Range: bytes ") - 1
        .wrapping_sub(1 as libc::c_int as libc::c_ulong);

    if (*r).headers_out.content_type_len == (*r).headers_out.content_type.len
        && (*r).headers_out.charset.len != 0
    {
        size = (size as libc::c_ulong).wrapping_add(
            (mem::size_of::<[libc::c_char; 11]>() as libc::c_ulong) // sizeof("; charset=") - 1
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                .wrapping_add((*r).headers_out.charset.len),
        ) as bindings::size_t;
    }

    (*ctx).boundary_header.data = bindings::ngx_pnalloc((*r).pool, size) as *mut bindings::u_char;
    if (*ctx).boundary_header.data.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    boundary = bindings::ngx_next_temp_number(0);

    /*
     * The boundary header of the range:
     * CRLF
     * "--0123456789" CRLF
     * "Content-Type: image/jpeg" CRLF
     * "Content-Range: bytes "
     */
    if (*r).headers_out.content_type_len == (*r).headers_out.content_type.len
        && (*r).headers_out.charset.len != 0
    {
        (*ctx).boundary_header.len = bindings::ngx_sprintf(
            (*ctx).boundary_header.data,
            b"\r\n--%0muA\r\nContent-Type: %V; charset=%V\r\nContent-Range: bytes \x00" as *const u8
                as *const libc::c_char,
            boundary,
            &mut (*r).headers_out.content_type as *mut bindings::ngx_str_t,
            &mut (*r).headers_out.charset as *mut bindings::ngx_str_t,
        )
        .offset_from((*ctx).boundary_header.data)
            as libc::c_long as bindings::size_t;
    } else if (*r).headers_out.content_type.len != 0 {
        (*ctx).boundary_header.len = bindings::ngx_sprintf(
            (*ctx).boundary_header.data,
            b"\r\n--%0muA\r\nContent-Type: %V\r\nContent-Range: bytes \x00" as *const u8
                as *const libc::c_char,
            boundary,
            &mut (*r).headers_out.content_type as *mut bindings::ngx_str_t,
        )
        .offset_from((*ctx).boundary_header.data)
            as libc::c_long as bindings::size_t;
    } else {
        (*ctx).boundary_header.len = bindings::ngx_sprintf(
            (*ctx).boundary_header.data,
            b"\r\n--%0muA\r\nContent-Range: bytes \x00" as *const u8 as *const libc::c_char,
            boundary,
        )
        .offset_from((*ctx).boundary_header.data)
            as libc::c_long as bindings::size_t;
    }
    (*r).headers_out.content_type.data = bindings::ngx_pnalloc(
        (*r).pool,
        (::std::mem::size_of::<[libc::c_char; 46]>() as libc::c_ulong) // sizeof("Content-Type: multipart/byteranges; boundary=") - 1
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_add(ngx_atomic_macro::NGX_ATOMIC_T_LEN as libc::c_ulong),
    ) as *mut bindings::u_char;
    if (*r).headers_out.content_type.data.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    (*r).headers_out.content_type_lowcase = ptr::null_mut();

    /* "Content-Type: multipart/byteranges; boundary=0123456789" */
    (*r).headers_out.content_type.len = bindings::ngx_sprintf(
        (*r).headers_out.content_type.data,
        b"multipart/byteranges; boundary=%0muA\x00" as *const u8 as *const libc::c_char,
        boundary,
    )
    .offset_from((*r).headers_out.content_type.data)
        as libc::c_long as bindings::size_t;

    (*r).headers_out.content_type_len = (*r).headers_out.content_type.len;

    (*r).headers_out.charset.len = 0;

    /* the size of the last boundary CRLF "--0123456789--" CRLF */
    len = (mem::size_of::<[libc::c_char; 5]>() as libc::c_ulong) // sizeof(CRLF "--")
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        .wrapping_add(ngx_atomic_macro::NGX_ATOMIC_T_LEN as libc::c_ulong)
        .wrapping_add(mem::size_of::<[libc::c_char; 5]>() as libc::c_ulong) // sizeof(CRLF "--")
        .wrapping_sub(1 as libc::c_int as libc::c_ulong) as bindings::off_t;

    range = (*ctx).ranges.elts as *mut ngx_http_range_t;

    for i in 0..(*ctx).ranges.nelts {
        /* the size of the range: "SSSS-EEEE/TTTT" CRLF CRLF */

        (*range.offset(i as isize)).content_range.data = bindings::ngx_pnalloc(
            (*r).pool,
            (3 as libc::c_int as libc::c_ulong)
                .wrapping_mul(
                    (mem::size_of::<[libc::c_char; 21]>() as libc::c_ulong) // sizeof("-9223372036854775808")
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                )
                .wrapping_add(2 as libc::c_int as libc::c_ulong)
                .wrapping_add(4 as libc::c_int as libc::c_ulong),
        ) as *mut bindings::u_char;
        if (*range.offset(i as isize)).content_range.data.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }

        (*range.offset(i as isize)).content_range.len = bindings::ngx_sprintf(
            (*range.offset(i as isize)).content_range.data,
            b"%O-%O/%O\r\n\r\n\x00" as *const u8 as *const libc::c_char,
            (*range.offset(i as isize)).start,
            (*range.offset(i as isize)).end - 1 as libc::c_int as libc::c_long,
            (*r).headers_out.content_length_n,
        )
        .offset_from((*range.offset(i as isize)).content_range.data)
            as libc::c_long
            as bindings::size_t;

        len = (len as libc::c_ulong).wrapping_add(
            (*ctx)
                .boundary_header
                .len
                .wrapping_add((*range.offset(i as isize)).content_range.len)
                .wrapping_add(
                    ((*range.offset(i as isize)).end - (*range.offset(i as isize)).start)
                        as libc::c_ulong,
                ),
        ) as bindings::off_t;
    }
    (*r).headers_out.content_length_n = len;

    if !(*r).headers_out.content_length.is_null() {
        (*(*r).headers_out.content_length).hash = 0;
        (*r).headers_out.content_length = ptr::null_mut();
    }

    return ngx_http_next_header_filter.expect("non-null function pointer")(r);
}

unsafe extern "C" fn ngx_http_range_not_satisfiable(
    mut r: *mut bindings::ngx_http_request_t,
) -> bindings::ngx_int_t {
    let mut content_range: *mut bindings::ngx_table_elt_t = ptr::null_mut();

    (*r).headers_out.status = bindings::NGX_HTTP_RANGE_NOT_SATISFIABLE as bindings::ngx_uint_t;

    content_range =
        bindings::ngx_list_push(&mut (*r).headers_out.headers) as *mut bindings::ngx_table_elt_t;
    if content_range.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }

    (*r).headers_out.content_range = content_range;

    (*content_range).hash = 1;
    ngx_str_set!(&mut (*content_range).key, "Content-Range");

    (*content_range).value.data = bindings::ngx_pnalloc(
        (*r).pool,
        (mem::size_of::<[libc::c_char; 9]>() as libc::c_ulong) // sizeof("bytes */")
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_add(
                (mem::size_of::<[libc::c_char; 21]>() as libc::c_ulong) // sizeof("-9223372036854775808")
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            ),
    ) as *mut bindings::u_char;

    if (*content_range).value.data.is_null() {
        (*content_range).hash = 0;
        (*r).headers_out.content_range = ptr::null_mut();
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }

    (*content_range).value.len = bindings::ngx_sprintf(
        (*content_range).value.data,
        b"bytes */%O\x00" as *const u8 as *const libc::c_char,
        (*r).headers_out.content_length_n,
    )
    .offset_from((*content_range).value.data) as libc::c_long
        as bindings::size_t;

    ngx_http_clear_content_length!(r);

    return bindings::NGX_HTTP_RANGE_NOT_SATISFIABLE as bindings::ngx_int_t;
}

unsafe extern "C" fn ngx_http_range_body_filter(
    mut r: *mut bindings::ngx_http_request_t,
    mut in_: *mut bindings::ngx_chain_t,
) -> bindings::ngx_int_t {
    let mut ctx: *mut ngx_http_range_filter_ctx_t = ptr::null_mut();

    if in_.is_null() {
        return ngx_http_next_body_filter.expect("non-null function pointer")(r, in_);
    }

    ctx = *ngx_http_get_module_ctx!(r, ngx_http_range_body_filter_module)
        as *mut ngx_http_range_filter_ctx_t;

    if ctx.is_null() {
        return ngx_http_next_body_filter.expect("non-null function pointer")(r, in_);
    }

    if (*ctx).ranges.nelts == 1 {
        return ngx_http_range_singlepart_body(r, ctx, in_);
    }

    /*
     * multipart ranges are supported only if whole body is in a single buffer
     */

    if ngx_buf_special!((*in_).buf) {
        return ngx_http_next_body_filter.expect("non-null function pointer")(r, in_);
    }

    if ngx_http_range_test_overlapped(r, ctx, in_) != bindings::NGX_OK as isize {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }

    return ngx_http_range_multipart_body(r, ctx, in_);
}

unsafe extern "C" fn ngx_http_range_test_overlapped(
    mut r: *mut bindings::ngx_http_request_t,
    mut ctx: *mut ngx_http_range_filter_ctx_t,
    mut in_: *mut bindings::ngx_chain_t,
) -> bindings::ngx_int_t {
    let mut current_block: u64;
    let mut start: bindings::off_t = 0;
    let mut last: bindings::off_t = 0;
    let mut buf: *mut bindings::ngx_buf_t = ptr::null_mut();
    let mut range = 0 as *mut ngx_http_range_t;
    let mut overlapped: bool = false;

    if (*ctx).offset != 0 {
        overlapped = true;
    } else {
        buf = (*in_).buf;

        if (*buf).last_buf() == 0 {
            start = (*ctx).offset;
            last = (*ctx).offset + ngx_buf_size!(buf);

            range = (*ctx).ranges.elts as *mut ngx_http_range_t;
            for i in 0..(*ctx).ranges.nelts {
                if start > (*range.offset(i as isize)).start
                    || last < (*range.offset(i as isize)).end
                {
                    overlapped = true;
                    break;
                }
            }
        }
    }
    match overlapped {
        false => {
            (*ctx).offset = ngx_buf_size!(buf);
            return bindings::NGX_OK as bindings::ngx_int_t;
        }
        true => {
            ngx_log_error!(
                bindings::NGX_LOG_ALERT as bindings::ngx_uint_t,
                (*(*r).connection).log,
                0 as libc::c_int,
                b"range in overlapped buffers\x00" as *const u8 as *const libc::c_char
            );
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }
    }
}

unsafe extern "C" fn ngx_http_range_singlepart_body(
    mut r: *mut bindings::ngx_http_request_t,
    mut ctx: *mut ngx_http_range_filter_ctx_t,
    mut in_: *mut bindings::ngx_chain_t,
) -> bindings::ngx_int_t {
    let mut start: bindings::off_t = 0;
    let mut last: bindings::off_t = 0;
    let mut rc: bindings::ngx_int_t = 0;
    let mut buf: *mut bindings::ngx_buf_t = ptr::null_mut();
    let mut cl: *mut bindings::ngx_chain_t = ptr::null_mut();
    let mut tl: *mut bindings::ngx_chain_t = ptr::null_mut();
    let mut out: *mut bindings::ngx_chain_t = ptr::null_mut();
    let mut ll: *mut *mut bindings::ngx_chain_t = &mut out;
    let mut range: *mut ngx_http_range_t = (*ctx).ranges.elts as *mut ngx_http_range_t;

    cl = in_;
    while !cl.is_null() {
        buf = (*cl).buf;

        start = (*ctx).offset;
        last = (*ctx).offset + ngx_buf_size!(buf);
        (*ctx).offset = last;
        ngx_log_debug!(
            bindings::NGX_LOG_DEBUG_HTTP as bindings::ngx_uint_t,
            (*(*r).connection).log,
            0,
            b"http range body buf: %O-%O\x00" as *const u8 as *const libc::c_char,
            start,
            last
        );

        if ngx_buf_special!(buf) {
            if !((*range).end <= start) {
                tl = bindings::ngx_alloc_chain_link((*r).pool);
                if tl.is_null() {
                    return bindings::NGX_ERROR as bindings::ngx_int_t;
                }
                (*tl).buf = buf;
                (*tl).next = ptr::null_mut();

                *ll = tl;
                ll = &mut (*tl).next
            }
        } else if (*range).end <= start || (*range).start >= last {
            ngx_log_debug!(
                bindings::NGX_LOG_DEBUG_HTTP as bindings::ngx_uint_t,
                (*(*r).connection).log,
                0,
                b"http range body skip\x00" as *const u8 as *const libc::c_char
            );
            if (*buf).in_file() != 0 {
                (*buf).file_pos = (*buf).file_last;
            }

            (*buf).pos = (*buf).last;
            (*buf).set_sync(1);
        } else {
            if (*range).start > start {
                if (*buf).in_file() != 0 {
                    (*buf).file_pos += (*range).start - start;
                }
                if ngx_buf_in_memory!(buf) {
                    (*buf).pos = (*buf)
                        .pos
                        .offset(((*range).start - start) as bindings::size_t as isize);
                }
            }

            if (*range).end <= last {
                if (*buf).in_file() != 0 {
                    (*buf).file_last -= last - (*range).end;
                }
                if ngx_buf_in_memory!(buf) {
                    (*buf).last = (*buf)
                        .last
                        .offset(-((last - (*range).end) as bindings::size_t as isize));
                }

                (*buf).set_last_buf(if r == (*r).main { 1 } else { 0 });
                (*buf).set_last_in_chain(1);

                tl = bindings::ngx_alloc_chain_link((*r).pool);
                if tl.is_null() {
                    return bindings::NGX_ERROR as bindings::ngx_int_t;
                }

                (*tl).buf = buf;
                (*tl).next = ptr::null_mut();

                *ll = tl;
                ll = &mut (*tl).next
            } else {
                tl = bindings::ngx_alloc_chain_link((*r).pool);
                if tl.is_null() {
                    return bindings::NGX_ERROR as bindings::ngx_int_t;
                }

                (*tl).buf = buf;
                (*tl).next = ptr::null_mut();

                *ll = tl;
                ll = &mut (*tl).next
            }
        }

        cl = (*cl).next;
    }

    rc = ngx_http_next_body_filter.expect("non-null function pointer")(r, out);

    while !out.is_null() {
        cl = out;
        out = (*out).next;
        ngx_free_chain!((*r).pool, cl);
    }
    return rc;
}

unsafe extern "C" fn ngx_http_range_multipart_body(
    mut r: *mut bindings::ngx_http_request_t,
    mut ctx: *mut ngx_http_range_filter_ctx_t,
    mut in_: *mut bindings::ngx_chain_t,
) -> bindings::ngx_int_t {
    let mut b: *mut bindings::ngx_buf_t = ptr::null_mut();
    let mut buf: *mut bindings::ngx_buf_t = ptr::null_mut();
    let mut out: *mut bindings::ngx_chain_t = ptr::null_mut();
    let mut hcl: *mut bindings::ngx_chain_t = ptr::null_mut();
    let mut rcl: *mut bindings::ngx_chain_t = ptr::null_mut();
    let mut dcl: *mut bindings::ngx_chain_t = ptr::null_mut();
    let mut range: *mut ngx_http_range_t = ptr::null_mut();

    let mut ll: *mut *mut bindings::ngx_chain_t = &mut out;
    buf = (*in_).buf;
    range = (*ctx).ranges.elts as *mut ngx_http_range_t;

    for i in 0..(*ctx).ranges.nelts {
        /*
         * The boundary header of the range:
         * CRLF
         * "--0123456789" CRLF
         * "Content-Type: image/jpeg" CRLF
         * "Content-Range: bytes "
         */

        b = bindings::ngx_pcalloc((*r).pool, mem::size_of::<bindings::ngx_buf_t>() as u64)
            as *mut bindings::ngx_buf_t;
        if b.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }

        (*b).set_memory(1);
        (*b).pos = (*ctx).boundary_header.data;
        (*b).last = (*ctx)
            .boundary_header
            .data
            .offset((*ctx).boundary_header.len as isize);

        hcl = bindings::ngx_alloc_chain_link((*r).pool);
        if hcl.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }

        (*hcl).buf = b;
        /* "SSSS-EEEE/TTTT" CRLF CRLF */

        b = bindings::ngx_pcalloc((*r).pool, mem::size_of::<bindings::ngx_buf_t>() as u64)
            as *mut bindings::ngx_buf_t;
        if b.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }
        (*b).set_temporary(1);
        (*b).pos = (*range.offset(i as isize)).content_range.data;
        (*b).last = (*range.offset(i as isize))
            .content_range
            .data
            .offset((*range.offset(i as isize)).content_range.len as isize);

        rcl = bindings::ngx_alloc_chain_link((*r).pool);
        if rcl.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }

        (*rcl).buf = b;
        /* the range data */

        b = bindings::ngx_pcalloc((*r).pool, mem::size_of::<bindings::ngx_buf_t>() as u64)
            as *mut bindings::ngx_buf_t;
        if b.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }

        (*b).set_in_file((*buf).in_file());
        (*b).set_temporary((*buf).temporary());
        (*b).set_memory((*buf).memory());
        (*b).set_mmap((*buf).mmap());
        (*b).file = (*buf).file;

        if (*buf).in_file() != 0 {
            (*b).file_pos = (*buf).file_pos + (*range.offset(i as isize)).start;
            (*b).file_last = (*buf).file_pos + (*range.offset(i as isize)).end
        }
        if ngx_buf_in_memory!(buf) {
            (*b).pos = (*buf)
                .pos
                .offset((*range.offset(i as isize)).start as bindings::size_t as isize);
            (*b).last = (*buf)
                .pos
                .offset((*range.offset(i as isize)).end as bindings::size_t as isize);
        }
        dcl = bindings::ngx_alloc_chain_link((*r).pool);
        if dcl.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }

        (*dcl).buf = b;
        *ll = hcl;
        (*hcl).next = rcl;
        (*rcl).next = dcl;
        ll = &mut (*dcl).next;
    }

    /* the last boundary CRLF "--0123456789--" CRLF  */
    b = bindings::ngx_pcalloc((*r).pool, mem::size_of::<bindings::ngx_buf_t>() as u64)
        as *mut bindings::ngx_buf_t;
    if b.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    (*b).set_temporary(1);
    (*b).set_last_buf(1);

    (*b).pos = bindings::ngx_pnalloc(
        (*r).pool,
        (mem::size_of::<[libc::c_char; 5]>() as libc::c_ulong) // sizeof(CRLF "--")
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_add(ngx_atomic_macro::NGX_ATOMIC_T_LEN as libc::c_ulong)
            .wrapping_add(::std::mem::size_of::<[libc::c_char; 5]>() as libc::c_ulong) // sizeof(CRLF "--")
            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
    ) as *mut bindings::u_char;

    if (*b).pos.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }

    (*b).last = ngx_string_macro::ngx_cpymem(
        (*b).pos,
        (*ctx).boundary_header.data,
        (mem::size_of::<[libc::c_char; 5]>() as libc::c_ulong) // sizeof(CRLF "--")
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
            .wrapping_add(ngx_atomic_macro::NGX_ATOMIC_T_LEN as libc::c_ulong) as usize,
    );

    *(*b).last = '-' as i32 as bindings::u_char;
    (*b).last = (*b).last.offset(1);
    *(*b).last = '-' as i32 as bindings::u_char;
    (*b).last = (*b).last.offset(1);
    *(*b).last = ngx_core_macro::CR as bindings::u_char;
    (*b).last = (*b).last.offset(1);
    *(*b).last = ngx_core_macro::CR as bindings::u_char;
    (*b).last = (*b).last.offset(1);

    hcl = bindings::ngx_alloc_chain_link((*r).pool);
    if hcl.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }

    (*hcl).buf = b;
    (*hcl).next = ptr::null_mut();
    *ll = hcl;
    return ngx_http_next_body_filter.expect("non-null function pointer")(r, out);
}

unsafe extern "C" fn ngx_http_range_header_filter_init(
    mut cf: *mut bindings::ngx_conf_t,
) -> bindings::ngx_int_t {
    ngx_http_next_header_filter = bindings::ngx_http_top_header_filter;
    bindings::ngx_http_top_header_filter = Some(ngx_http_range_header_filter);
    return bindings::NGX_OK as bindings::ngx_int_t;
}

unsafe extern "C" fn ngx_http_range_body_filter_init(
    mut cf: *mut bindings::ngx_conf_t,
) -> bindings::ngx_int_t {
    ngx_http_next_body_filter = bindings::ngx_http_top_body_filter;
    bindings::ngx_http_top_body_filter = Some(ngx_http_range_body_filter);
    return bindings::NGX_OK as bindings::ngx_int_t;
}
