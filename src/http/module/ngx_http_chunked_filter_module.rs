use crate::bindings;
use crate::core::ngx_core_macro;
use crate::core::ngx_module_macro;
use crate::core::ngx_string_macro;
use std::mem;
use std::ptr;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ngx_http_chunked_filter_ctx_t {
    pub free: *mut bindings::ngx_chain_t,
    pub busy: *mut bindings::ngx_chain_t,
}

static mut ngx_http_chunked_filter_module_ctx: bindings::ngx_http_module_t = unsafe {
    {
        let init = bindings::ngx_http_module_t {
            preconfiguration: None,
            postconfiguration: Some(ngx_http_chunked_filter_init),
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
pub static mut ngx_http_chunked_filter_module: bindings::ngx_module_t = unsafe {
    {
        let init = bindings::ngx_module_t {
            ctx_index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as usize,
            index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as usize,
            name: ptr::null_mut(),
            spare0: 0,
            spare1: 0,
            version: bindings::nginx_version as bindings::ngx_uint_t,
            signature: ngx_module_macro::NGX_MODULE_SIGNATURE as *const u8 as *const i8,
            ctx: &ngx_http_chunked_filter_module_ctx as *const bindings::ngx_http_module_t
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

unsafe extern "C" fn ngx_http_chunked_header_filter(
    mut r: *mut bindings::ngx_http_request_t,
) -> bindings::ngx_int_t {
    let mut clcf = 0 as *mut bindings::ngx_http_core_loc_conf_t;
    let mut ctx = 0 as *mut ngx_http_chunked_filter_ctx_t;

    if (*r).headers_out.status == bindings::NGX_HTTP_NOT_MODIFIED as usize
        || (*r).headers_out.status == bindings::NGX_HTTP_NO_CONTENT as usize
        || (*r).headers_out.status < bindings::NGX_HTTP_OK as usize
        || r != (*r).main
        || (*r).method == bindings::NGX_HTTP_HEAD as usize
    {
        return ngx_http_next_header_filter.expect("non-null function pointer")(r);
    }
    if (*r).headers_out.content_length_n == -1 || (*r).expect_trailers() != 0 {
        clcf = *ngx_http_get_module_loc_conf!(r, bindings::ngx_http_core_module)
            as *mut bindings::ngx_http_core_loc_conf_t;

        if (*r).http_version >= bindings::NGX_HTTP_VERSION_11 as usize
            && (*clcf).chunked_transfer_encoding != 0
        {
            if (*r).expect_trailers() != 0 {
                ngx_http_clear_content_length!(r);
            }

            (*r).set_chunked(1);
            ctx = bindings::ngx_pcalloc(
                (*r).pool,
                mem::size_of::<ngx_http_chunked_filter_ctx_t>() as u64,
            ) as *mut ngx_http_chunked_filter_ctx_t;
            if ctx.is_null() {
                return bindings::NGX_ERROR as bindings::ngx_int_t;
            }

            ngx_http_set_ctx!(r, ctx as *mut libc::c_void, ngx_http_chunked_filter_module);
        } else if (*r).headers_out.content_length_n == -1 {
            (*r).set_keepalive(0);
        }
    }

    return ngx_http_next_header_filter.expect("non-null function pointer")(r);
}

unsafe extern "C" fn ngx_http_chunked_body_filter(
    mut r: *mut bindings::ngx_http_request_t,
    mut in_0: *mut bindings::ngx_chain_t,
) -> bindings::ngx_int_t {
    let mut chunk = 0 as *mut u8;
    let mut size: bindings::off_t = 0;
    let mut rc: bindings::ngx_int_t = 0;
    let mut b = 0 as *mut bindings::ngx_buf_t;
    let mut out = 0 as *mut bindings::ngx_chain_t;
    let mut cl = 0 as *mut bindings::ngx_chain_t;
    let mut tl = 0 as *mut bindings::ngx_chain_t;
    let mut ll = 0 as *mut *mut bindings::ngx_chain_t;
    let mut ctx = 0 as *mut ngx_http_chunked_filter_ctx_t;
    if in_0.is_null() || (*r).chunked() == 0 || (*r).header_only() as libc::c_int != 0 {
        return ngx_http_next_body_filter.expect("non-null function pointer")(r, in_0);
    }
    ctx = *ngx_http_get_module_ctx!(r, ngx_http_chunked_filter_module)
        as *mut ngx_http_chunked_filter_ctx_t;
    out = ptr::null_mut();
    ll = &mut out;
    size = 0;
    cl = in_0;
    loop {
        ngx_log_debug!(
            bindings::NGX_LOG_DEBUG_HTTP as bindings::ngx_uint_t,
            (*(*r).connection).log,
            0,
            b"http chunk: %O\x00" as *const u8 as *const i8,
            ngx_buf_size!((*cl).buf)
        );

        size += ngx_buf_size!((*cl).buf);

        if (*(*cl).buf).flush() as libc::c_int != 0
            || (*(*cl).buf).sync() as libc::c_int != 0
            || ngx_buf_in_memory!((*cl).buf)
            || (*(*cl).buf).in_file() as libc::c_int != 0
        {
            tl = bindings::ngx_alloc_chain_link((*r).pool);
            if tl.is_null() {
                return bindings::NGX_ERROR as bindings::ngx_int_t;
            }
            (*tl).buf = (*cl).buf;
            *ll = tl;
            ll = &mut (*tl).next;
        }

        if (*cl).next.is_null() {
            break;
        }

        cl = (*cl).next;
    }

    if size != 0 {
        tl = bindings::ngx_chain_get_free_buf((*r).pool, &mut (*ctx).free);
        if tl.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }

        b = (*tl).buf;
        chunk = (*b).start;
        if chunk.is_null() {
            /* the "0000000000000000" is 64-bit hexadecimal string */
            chunk = bindings::ngx_palloc(
                (*r).pool,
                // sizeof("0000000000000000" CRLF) - 1
                (mem::size_of::<[i8; 19]>() as u64).wrapping_sub(1),
            ) as *mut u8;
            if chunk.is_null() {
                return bindings::NGX_ERROR as bindings::ngx_int_t;
            }

            (*b).start = chunk;
            // sizeof("0000000000000000" CRLF) - 1
            (*b).end = chunk.offset(mem::size_of::<[i8; 19]>() as isize).offset(-1);
        }
        (*b).tag = &mut ngx_http_chunked_filter_module as *mut bindings::ngx_module_t
            as bindings::ngx_buf_tag_t;
        (*b).set_memory(0);
        (*b).set_temporary(1);
        (*b).pos = chunk;
        (*b).last = bindings::ngx_sprintf(chunk, b"%xO\r\n\x00" as *const u8 as *const i8, size);
        (*tl).next = out;
        out = tl
    }
    if (*(*cl).buf).last_buf() != 0 {
        tl = ngx_http_chunked_create_trailers(r, ctx);
        if tl.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }
        (*(*cl).buf).set_last_buf(0);

        *ll = tl;

        if size == 0 {
            (*(*tl).buf).pos = (*(*tl).buf).pos.offset(2);
        }
    } else if size > 0 as libc::c_int as libc::c_long {
        tl = bindings::ngx_chain_get_free_buf((*r).pool, &mut (*ctx).free);
        if tl.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }

        b = (*tl).buf;

        (*b).tag = &mut ngx_http_chunked_filter_module as *mut bindings::ngx_module_t
            as bindings::ngx_buf_tag_t;
        (*b).set_temporary(0);
        (*b).set_memory(1);
        (*b).pos = ngx_core_macro::CRLF.as_ptr() as *mut u8;
        (*b).last = (*b).pos.offset(2);
        *ll = tl;
    } else {
        *ll = ptr::null_mut();
    }
    rc = ngx_http_next_body_filter.expect("non-null function pointer")(r, out);

    bindings::ngx_chain_update_chains(
        (*r).pool,
        &mut (*ctx).free,
        &mut (*ctx).busy,
        &mut out,
        &mut ngx_http_chunked_filter_module as *mut bindings::ngx_module_t
            as bindings::ngx_buf_tag_t,
    );

    return rc;
}

unsafe extern "C" fn ngx_http_chunked_create_trailers(
    mut r: *mut bindings::ngx_http_request_t,
    mut ctx: *mut ngx_http_chunked_filter_ctx_t,
) -> *mut bindings::ngx_chain_t {
    let mut len: bindings::size_t = 0;
    let mut b = 0 as *mut bindings::ngx_buf_t;
    let mut i: bindings::ngx_uint_t = 0;
    let mut cl = 0 as *mut bindings::ngx_chain_t;
    let mut part = 0 as *mut bindings::ngx_list_part_t;
    let mut header = 0 as *mut bindings::ngx_table_elt_t;

    len = 0;
    part = &mut (*r).headers_out.trailers.part;
    header = (*part).elts as *mut bindings::ngx_table_elt_t;

    i = 0;
    loop {
        if i >= (*part).nelts {
            if (*part).next.is_null() {
                break;
            }
            part = (*part).next;
            header = (*part).elts as *mut bindings::ngx_table_elt_t;
            i = 0;
        }
        if !((*header.offset(i as isize)).hash == 0) {
            len = (len as libc::c_ulong).wrapping_add(
                (*header.offset(i as isize))
                    .key
                    .len
                    .wrapping_add(mem::size_of::<[libc::c_char; 3]>() as u64) // sizeof(": ")
                    .wrapping_sub(1)
                    .wrapping_add((*header.offset(i as isize)).value.len)
                    .wrapping_add(mem::size_of::<[libc::c_char; 3]>() as u64)
                    .wrapping_sub(1),
            ) as bindings::size_t;
        }
        i = i.wrapping_add(1);
    }

    cl = bindings::ngx_chain_get_free_buf((*r).pool, &mut (*ctx).free);
    if cl.is_null() {
        return ptr::null_mut();
    }
    b = (*cl).buf;
    (*b).tag = &mut ngx_http_chunked_filter_module as *mut bindings::ngx_module_t
        as bindings::ngx_buf_tag_t;
    (*b).set_temporary(0);
    (*b).set_memory(1);
    (*b).set_last_buf(1);
    if len == 0 {
        (*b).pos = b"\r\n0\r\n\r\n\x00" as *const u8 as *const i8 as *mut u8;
        (*b).last = (*b)
            .pos
            .offset(mem::size_of::<[i8; 8]>() as isize)
            .offset(-1);
        return cl;
    }

    len = len.wrapping_add((mem::size_of::<[i8; 8]>() as u64).wrapping_sub(1));

    (*b).pos = bindings::ngx_palloc((*r).pool, len) as *mut u8;
    if (*b).pos.is_null() {
        return ptr::null_mut();
    }

    (*b).last = (*b).pos;

    let fresh1 = (*b).last;
    (*b).last = (*b).last.offset(1);
    *fresh1 = ngx_core_macro::CR;
    let fresh2 = (*b).last;
    (*b).last = (*b).last.offset(1);
    *fresh2 = ngx_core_macro::LF;
    let fresh3 = (*b).last;
    (*b).last = (*b).last.offset(1);
    *fresh3 = '0' as i32 as u8;
    let fresh4 = (*b).last;
    (*b).last = (*b).last.offset(1);
    *fresh4 = ngx_core_macro::CR;
    let fresh5 = (*b).last;
    (*b).last = (*b).last.offset(1);
    *fresh5 = ngx_core_macro::LF;

    part = &mut (*r).headers_out.trailers.part;
    header = (*part).elts as *mut bindings::ngx_table_elt_t;
    i = 0;
    loop {
        if i >= (*part).nelts {
            if (*part).next.is_null() {
                break;
            }
            part = (*part).next;
            header = (*part).elts as *mut bindings::ngx_table_elt_t;
            i = 0;
        }

        if !((*header.offset(i as isize)).hash == 0) {
            ngx_log_debug!(
                bindings::NGX_LOG_DEBUG_HTTP,
                (*(*r).connection).log,
                0,
                b"http trailer: \"%V: %V\"\x00" as *const u8 as *const i8,
                &mut (*header.offset(i as isize)).key as *mut bindings::ngx_str_t,
                &mut (*header.offset(i as isize)).value as *mut bindings::ngx_str_t
            );

            (*b).last = ngx_string_macro::ngx_cpymem(
                (*b).last as *mut u8,
                (*header.offset(i as isize)).key.data as *mut u8,
                (*header.offset(i as isize)).key.len as usize,
            );
            // ptr::copy_nonoverlapping(
            //     (*header.offset(i as isize)).key.data,
            //     (*b).last,
            //     (*header.offset(i as isize)).key.len as usize,
            // );
            // (*b).last = (*b)
            //     .last
            //     .offset((*header.offset(i as isize)).key.len as isize);

            let fresh6 = (*b).last;
            (*b).last = (*b).last.offset(1);
            *fresh6 = ':' as i32 as u8;

            let fresh7 = (*b).last;
            (*b).last = (*b).last.offset(1);
            *fresh7 = ' ' as i32 as u8;

            (*b).last = ngx_string_macro::ngx_cpymem(
                (*b).last as *mut u8,
                (*header.offset(i as isize)).value.data as *mut u8,
                (*header.offset(i as isize)).value.len as usize,
            );
            // ptr::copy_nonoverlapping(
            //     (*header.offset(i as isize)).value.data,
            //     (*b).last,
            //     (*header.offset(i as isize)).key.value as usize,
            // );
            // (*b).last = (*b)
            //     .last
            //     .offset((*header.offset(i as isize)).value.len as isize);

            let fresh8 = (*b).last;
            (*b).last = (*b).last.offset(1);
            *fresh8 = ngx_core_macro::CR;
            let fresh9 = (*b).last;
            (*b).last = (*b).last.offset(1);
            *fresh9 = ngx_core_macro::LF;
        }
        i = i.wrapping_add(1)
    }
    let fresh10 = (*b).last;
    (*b).last = (*b).last.offset(1);
    *fresh10 = ngx_core_macro::CR;
    let fresh11 = (*b).last;
    (*b).last = (*b).last.offset(1);
    *fresh11 = ngx_core_macro::LF;
    return cl;
}

unsafe extern "C" fn ngx_http_chunked_filter_init(
    _: *mut bindings::ngx_conf_t,
) -> bindings::ngx_int_t {
    ngx_http_next_header_filter = bindings::ngx_http_top_header_filter;
    bindings::ngx_http_top_header_filter = Some(ngx_http_chunked_header_filter);

    ngx_http_next_body_filter = bindings::ngx_http_top_body_filter;
    bindings::ngx_http_top_body_filter = Some(ngx_http_chunked_body_filter);
    return bindings::NGX_OK as bindings::ngx_int_t;
}
