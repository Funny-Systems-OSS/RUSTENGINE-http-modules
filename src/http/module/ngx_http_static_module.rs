use crate::bindings;
use crate::core::ngx_module_macro;
use crate::core::ngx_string_macro;

use std::ptr;

#[no_mangle]
static ngx_http_static_module_ctx: bindings::ngx_http_module_t = {
    let init = bindings::ngx_http_module_t {
        preconfiguration: None,
        postconfiguration: Some(ngx_http_static_init),
        create_main_conf: None,
        init_main_conf: None,
        create_srv_conf: None,
        merge_srv_conf: None,
        create_loc_conf: None,
        merge_loc_conf: None,
    };
    init
};
#[no_mangle]
pub static mut ngx_http_static_module: bindings::ngx_module_t = {
    let init = bindings::ngx_module_t {
        ctx_index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as usize,
        index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as usize,
        name: ptr::null_mut(),
        spare0: 0,
        spare1: 0,
        version: bindings::nginx_version as usize,
        signature: ngx_module_macro::NGX_MODULE_SIGNATURE as *const u8 as *const libc::c_char,
        ctx: &ngx_http_static_module_ctx as *const bindings::ngx_http_module_t
            as *mut bindings::ngx_http_module_t as *mut libc::c_void,
        commands: ptr::null_mut(),
        type_: bindings::NGX_HTTP_MODULE as usize,
        init_master: None,  /* init master */
        init_module: None,  /* init module */
        init_process: None, /* init process */
        init_thread: None,  /* init thread */
        exit_thread: None,  /* exit thread */
        exit_process: None, /* exit process */
        exit_master: None,  /* exit master */
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
};

unsafe extern "C" fn ngx_http_static_handler(
    r_: *mut bindings::ngx_http_request_t,
) -> bindings::ngx_int_t {
    let mut root: bindings::size_t = 0;
    let mut path = bindings::ngx_str_t {
        len: 0,
        data: 0 as *mut bindings::u_char,
    };
    let mut rc: bindings::ngx_int_t = 0;
    let mut level: bindings::ngx_uint_t = 0;
    if (*r_).method
        & (bindings::NGX_HTTP_GET as usize
            | bindings::NGX_HTTP_HEAD as usize
            | bindings::NGX_HTTP_POST as usize)
        == 0
    {
        return bindings::NGX_HTTP_NOT_ALLOWED as bindings::ngx_int_t;
    }
    if *(*r_).uri.data.offset(
        (*r_)
            .uri
            .len
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
    ) as libc::c_int
        == '/' as i32
    {
        return bindings::NGX_DECLINED as bindings::ngx_int_t;
    }
    let log: *mut bindings::ngx_log_t = (*(*r_).connection).log;
    /*
     * ngx_http_map_uri_to_path() allocates memory for terminating '\0'
     * so we do not need to reserve memory for '/' for possible redirect
     */
    let mut last: *mut bindings::u_char =
        bindings::ngx_http_map_uri_to_path(r_, &mut path, &mut root, 0);
    if last.is_null() {
        return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
    }

    path.len = last.offset_from(path.data) as bindings::size_t;

    ngx_log_debug!(
        bindings::NGX_LOG_DEBUG_HTTP,
        log,
        0,
        b"http filename: \"%s\"\x00" as *const u8 as *const libc::c_char,
        path.data
    );

    let clcf: *mut bindings::ngx_http_core_loc_conf_t =
        *ngx_http_get_module_loc_conf!(r_, bindings::ngx_http_core_module)
            as *mut bindings::ngx_http_core_loc_conf_t;

    let mut of: bindings::ngx_open_file_info_t = bindings::ngx_open_file_info_t {
        fd: 0,
        uniq: 0,
        mtime: 0,
        size: 0,
        fs_size: 0,
        directio: 0,
        read_ahead: 0,
        err: 0,
        failed: 0 as *mut libc::c_char,
        valid: 0,
        min_uses: 0,
        disable_symlinks_from: 0,
        _bitfield_align_1: [0; 0],
        _bitfield_1: bindings::ngx_open_file_info_t::new_bitfield_1(
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ),
        __bindgen_padding_0: [0; 3],
    };
    of.read_ahead = (*clcf).read_ahead;
    of.directio = (*clcf).directio;
    of.valid = (*clcf).open_file_cache_valid;
    of.min_uses = (*clcf).open_file_cache_min_uses;
    of.set_errors((*clcf).open_file_cache_errors as libc::c_uint);
    of.set_events((*clcf).open_file_cache_events as libc::c_uint);

    if bindings::ngx_http_set_disable_symlinks(r_, clcf, &mut path, &mut of)
        != bindings::NGX_OK as bindings::ngx_int_t
    {
        return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as isize;
    }
    if bindings::ngx_open_cached_file((*clcf).open_file_cache, &mut path, &mut of, (*r_).pool)
        != bindings::NGX_OK as bindings::ngx_int_t
    {
        match of.err as i32 {
            0 => return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t,
            bindings::NGX_ENOENT | bindings::NGX_ENOTDIR | bindings::NGX_ENAMETOOLONG => {
                level = bindings::NGX_LOG_ERR as bindings::ngx_uint_t;
                rc = bindings::NGX_HTTP_NOT_FOUND as bindings::ngx_int_t;
            }
            bindings::NGX_EACCES | bindings::NGX_EMLINK | bindings::NGX_ELOOP => {
                level = bindings::NGX_LOG_ERR as bindings::ngx_uint_t;
                rc = bindings::NGX_HTTP_FORBIDDEN as bindings::ngx_int_t
            }
            _ => {
                level = bindings::NGX_LOG_CRIT as bindings::ngx_uint_t;
                rc = bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t
            }
        }
        if rc != bindings::NGX_HTTP_NOT_FOUND as isize || (*clcf).log_not_found != 0 {
            ngx_log_error!(
                level,
                log,
                of.err,
                b"%s \"%s\" failed\x00" as *const u8 as *const libc::c_char,
                of.failed,
                path.data
            );
        }
        return rc;
    }

    (*r_).set_root_tested(((*r_).error_page() == 0) as libc::c_int as libc::c_uint);

    ngx_log_debug!(
        bindings::NGX_LOG_DEBUG_HTTP,
        log,
        0,
        b"http static fd: %d\x00" as *const u8 as *const libc::c_char,
        of.fd
    );

    if of.is_dir() != 0 {
        ngx_log_debug!(
            bindings::NGX_LOG_DEBUG_HTTP,
            log,
            0,
            b"http dir\x00" as *const u8 as *const libc::c_char
        );

        ngx_http_clear_location!(r_);

        (*r_).headers_out.location = bindings::ngx_list_push(&mut (*r_).headers_out.headers)
            as *mut bindings::ngx_table_elt_t;
        if (*r_).headers_out.location.is_null() {
            return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
        }

        let mut len: bindings::size_t = (*r_).uri.len.wrapping_add(1);

        let mut location: *mut bindings::u_char = ptr::null_mut();
        if (*clcf).alias == 0 && (*r_).args.len == 0 as libc::c_int as libc::c_ulong {
            location = path.data.offset(root as isize);

            *last = '/' as i32 as bindings::u_char;
        } else {
            if (*r_).args.len != 0 {
                len = (len as libc::c_ulong).wrapping_add((*r_).args.len.wrapping_add(1))
                    as bindings::size_t;
            }

            location = bindings::ngx_pnalloc((*r_).pool, len) as *mut bindings::u_char;
            if location.is_null() {
                ngx_http_clear_location!(r_);
                return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
            }

            last = ngx_string_macro::ngx_cpymem(location, (*r_).uri.data, (*r_).uri.len as usize);
            // ptr::copy_nonoverlapping((*r_).uri.data, location, (*r_).uri.len as usize);
            // last = location.offset((*r_).uri.len as isize);

            *last = '/' as i32 as bindings::u_char;

            if (*r_).args.len != 0 {
                last = last.offset(1);
                *last = '?' as i32 as bindings::u_char;

                last = last.offset(1);
                ngx_string_macro::ngx_memcpy(last, (*r_).args.data, (*r_).args.len as usize);
            }
        }

        (*(*r_).headers_out.location).hash = 1 as libc::c_int as bindings::ngx_uint_t;
        ngx_str_set!(&mut (*(*r_).headers_out.location).key, b"Location\x00");
        (*(*r_).headers_out.location).value.len = len;
        (*(*r_).headers_out.location).value.data = location;

        return bindings::NGX_HTTP_MOVED_PERMANENTLY as bindings::ngx_int_t;
    }
    if cfg!(NGX_WIN32)
    /* the not regular files are probably Unix specific */
    {
        if of.is_file() == 0 {
            ngx_log_error!(
                bindings::NGX_LOG_CRIT as usize,
                log,
                0,
                b"\"%s\" is not a regular file\x00" as *const u8 as *const libc::c_char,
                path.data
            );
            return bindings::NGX_HTTP_NOT_FOUND as bindings::ngx_int_t;
        }
    }

    if (*r_).method == bindings::NGX_HTTP_POST as usize {
        return bindings::NGX_HTTP_NOT_ALLOWED as bindings::ngx_int_t;
    }

    rc = bindings::ngx_http_discard_request_body(r_);

    if rc != bindings::NGX_OK as isize {
        return rc;
    }

    (*log).action =
        b"sending response to client\x00" as *const u8 as *const libc::c_char as *mut libc::c_char;

    (*r_).headers_out.status = bindings::NGX_HTTP_OK as bindings::ngx_uint_t;
    (*r_).headers_out.content_length_n = of.size;
    (*r_).headers_out.last_modified_time = of.mtime;

    if bindings::ngx_http_set_etag(r_) != bindings::NGX_OK as bindings::ngx_int_t {
        return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
    }
    if bindings::ngx_http_set_content_type(r_) != bindings::NGX_OK as bindings::ngx_int_t {
        return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
    }

    if r_ != (*r_).main && of.size == 0 as libc::c_int as libc::c_long {
        return bindings::ngx_http_send_header(r_);
    }

    (*r_).set_allow_ranges(1 as libc::c_int as libc::c_uint);

    /* we need to allocate all before the header would be sent */

    let b: *mut bindings::ngx_buf_t = ngx_calloc_buf!((*r_).pool) as *mut bindings::ngx_buf_t;
    if b.is_null() {
        return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
    }

    (*b).file = bindings::ngx_pcalloc(
        (*r_).pool,
        ::std::mem::size_of::<bindings::ngx_file_t>() as libc::c_ulong,
    ) as *mut bindings::ngx_file_t;
    if (*b).file.is_null() {
        return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
    }

    rc = bindings::ngx_http_send_header(r_);
    if rc == bindings::NGX_ERROR as bindings::ngx_int_t
        || rc > bindings::NGX_OK as bindings::ngx_int_t
        || (*r_).header_only() as libc::c_int != 0
    {
        return rc;
    }

    (*b).file_pos = 0 as libc::c_int as bindings::off_t;
    (*b).file_last = of.size;

    (*b).set_in_file(if (*b).file_last != 0 {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    } as libc::c_uint);
    (*b).set_last_buf(if r_ == (*r_).main {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    } as libc::c_uint);
    (*b).set_last_in_chain(1 as libc::c_int as libc::c_uint);

    (*(*b).file).fd = of.fd;
    (*(*b).file).name = path;
    (*(*b).file).log = log;
    (*(*b).file).set_directio(of.is_directio());

    let mut out = bindings::ngx_chain_t {
        buf: ptr::null_mut(),
        next: ptr::null_mut(),
    };
    out.buf = b;
    out.next = ptr::null_mut();
    return bindings::ngx_http_output_filter(r_, &mut out);
}

unsafe extern "C" fn ngx_http_static_init(
    mut cf: *mut bindings::ngx_conf_t,
) -> bindings::ngx_int_t {
    let cmcf: *mut bindings::ngx_http_core_main_conf_t =
        *ngx_http_conf_get_module_main_conf!(cf, bindings::ngx_http_core_module)
            as *mut bindings::ngx_http_core_main_conf_t;

    let h: *mut bindings::ngx_http_handler_pt = bindings::ngx_array_push(
        &mut (*(*cmcf)
            .phases
            .as_mut_ptr()
            .offset(bindings::ngx_http_phases::NGX_HTTP_CONTENT_PHASE as libc::c_int as isize))
        .handlers,
    ) as *mut bindings::ngx_http_handler_pt;
    if h.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    *h = Some(ngx_http_static_handler);
    return bindings::NGX_OK as bindings::ngx_int_t;
}
