use crate::bindings;
use crate::core::ngx_conf_file_macro;
use crate::core::ngx_module_macro;
use crate::core::ngx_string_macro;
use std::ffi;
use std::mem;
use std::ptr;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ngx_http_index_t {
    pub name: bindings::ngx_str_t,
    pub lengths: *mut bindings::ngx_array_t,
    pub values: *mut bindings::ngx_array_t,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ngx_http_index_loc_conf_t {
    pub indices: *mut bindings::ngx_array_t,
    pub max_index_len: bindings::size_t,
}

// #[no_mangle]
// static NGX_HTTP_INDEX_MODULE_COMMAND_INDEX: &[u8; 6] = b"index\0";

pub const NGX_HTTP_DEFAULT_INDEX: [libc::c_char; 11] =
    unsafe { *::std::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"index.html\x00") };

// Initialized in run_static_initializers
#[no_mangle]
static mut ngx_http_index_commands: [bindings::ngx_command_t; 2] = [bindings::ngx_command_t {
    name: bindings::ngx_str_t {
        len: 0,
        data: ptr::null_mut(),
    },
    type_: 0,
    set: None,
    conf: 0,
    offset: 0,
    post: ptr::null_mut(),
}; 2];

#[no_mangle]
static mut ngx_http_index_module_ctx: bindings::ngx_http_module_t = {
    let init = bindings::ngx_http_module_t {
        preconfiguration: None,
        postconfiguration: Some(ngx_http_index_init),
        create_main_conf: None,
        init_main_conf: None,
        create_srv_conf: None,
        merge_srv_conf: None,
        create_loc_conf: Some(ngx_http_index_create_loc_conf),
        merge_loc_conf: Some(ngx_http_index_merge_loc_conf),
    };
    init
};

#[no_mangle]
pub static mut ngx_http_index_module: bindings::ngx_module_t = unsafe {
    {
        let init = bindings::ngx_module_t {
            ctx_index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as usize,
            index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as usize,
            name: ptr::null_mut(),
            spare0: 0,
            spare1: 0,
            version: bindings::nginx_version as usize,
            signature: ngx_module_macro::NGX_MODULE_SIGNATURE as *const u8 as *const i8,
            ctx: &ngx_http_index_module_ctx as *const bindings::ngx_http_module_t
                as *mut bindings::ngx_http_module_t as *mut libc::c_void,
            commands: ngx_http_index_commands.as_ptr() as *mut bindings::ngx_command_t,
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

/*
 * Try to open/test the first index file before the test of directory
 * existence because valid requests should prevail over invalid ones.
 * If open()/stat() of a file will fail then stat() of a directory
 * should be faster because kernel may have already cached some data.
 * Besides, Win32 may return ERROR_PATH_NOT_FOUND (NGX_ENOTDIR) at once.
 * Unix has ENOTDIR error; however, it's less helpful than Win32's one:
 * it only indicates that path points to a regular file, not a directory.
 */
#[no_mangle]
pub unsafe extern "C" fn ngx_http_index_handler(
    r: *mut bindings::ngx_http_request_t,
) -> bindings::ngx_int_t {
    let mut len: bindings::size_t = 0;
    let mut reserve: bindings::size_t = 0;
    let mut rc: bindings::ngx_int_t = 0;
    let mut uri = bindings::ngx_str_t {
        len: 0,
        data: ptr::null_mut(),
    };
    let mut index = 0 as *mut ngx_http_index_t;
    let mut of = bindings::ngx_open_file_info_t {
        fd: 0,
        uniq: 0,
        mtime: 0,
        size: 0,
        fs_size: 0,
        directio: 0,
        read_ahead: 0,
        err: 0,
        failed: ptr::null_mut(),
        valid: 0,
        min_uses: 0,
        disable_symlinks_from: 0,
        _bitfield_align_1: [0; 0],
        _bitfield_1: bindings::ngx_open_file_info_t::new_bitfield_1(
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ),
        __bindgen_padding_0: [0; 3],
    };
    let mut code: bindings::ngx_http_script_code_pt = None;
    let mut e = bindings::ngx_http_script_engine_t {
        ip: 0 as *mut u8,
        pos: 0 as *mut u8,
        sp: 0 as *mut bindings::ngx_http_variable_value_t,
        buf: bindings::ngx_str_t {
            len: 0,
            data: ptr::null_mut(),
        },
        line: bindings::ngx_str_t {
            len: 0,
            data: ptr::null_mut(),
        },
        args: 0 as *mut u8,
        _bitfield_align_1: [0; 0],
        _bitfield_1: bindings::ngx_http_script_engine_t::new_bitfield_1(0, 0, 0, 0, 0),
        status: 0,
        request: ptr::null_mut(),
    };
    let mut lcode: bindings::ngx_http_script_len_code_pt = None;
    if *(*r).uri.data.offset((*r).uri.len.wrapping_sub(1) as isize) as i32 != '/' as i32 {
        return bindings::NGX_DECLINED as bindings::ngx_int_t;
    }
    if (*r).method
        & (bindings::NGX_HTTP_GET | bindings::NGX_HTTP_HEAD | bindings::NGX_HTTP_POST) as usize
        == 0
    {
        return bindings::NGX_DECLINED as bindings::ngx_int_t;
    }

    let mut ilcf: *mut ngx_http_index_loc_conf_t =
        *ngx_http_get_module_loc_conf!(r, ngx_http_index_module) as *mut ngx_http_index_loc_conf_t;

    let mut clcf: *mut bindings::ngx_http_core_loc_conf_t =
        *ngx_http_get_module_loc_conf!(r, bindings::ngx_http_core_module)
            as *mut bindings::ngx_http_core_loc_conf_t;

    let mut allocated: bindings::size_t = 0;
    let mut root: bindings::size_t = 0;
    let mut dir_tested: bindings::ngx_uint_t = 0;
    let mut name = ptr::null_mut();
    /* suppress MSVC warning */
    let mut path = bindings::ngx_str_t {
        len: 0,
        data: ptr::null_mut(),
    };

    index = (*(*ilcf).indices).elts as *mut ngx_http_index_t;
    let mut i: bindings::ngx_uint_t = 0;
    while i < (*(*ilcf).indices).nelts {
        if (*index.offset(i as isize)).lengths.is_null() {
            if *(*index.offset(i as isize)).name.data.offset(0) as i32 == '/' as i32 {
                // return bindings::NGX_DECLINED as bindings::ngx_int_t;
                return bindings::ngx_http_internal_redirect(
                    r,
                    &mut (*index.offset(i as isize)).name,
                    &mut (*r).args,
                );
            }

            reserve = (*ilcf).max_index_len;
            len = (*index.offset(i as isize)).name.len
        } else {
            ngx_memzero!(&mut e, mem::size_of::<bindings::ngx_http_script_engine_t>());

            e.ip = (*(*index.offset(i as isize)).lengths).elts as *mut u8;
            e.request = r;
            e.set_flushed(1);

            /* 1 is for terminating '\0' as in static names */
            len = 1;

            while *(e.ip as *mut u64) != 0 {
                lcode = *(e.ip as *mut bindings::ngx_http_script_len_code_pt);
                len = (len as libc::c_ulong)
                    .wrapping_add(lcode.expect("non-null function pointer")(&mut e))
                    as bindings::size_t;
            }

            /* 16 bytes are preallocation */

            reserve = len.wrapping_add(16);
        }

        if reserve > allocated {
            name = bindings::ngx_http_map_uri_to_path(r, &mut path, &mut root, reserve);
            if name.is_null() {
                return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
            }

            allocated = path.data.offset(path.len as isize).offset_from(name) as u64;
        }
        if (*index.offset(i as isize)).values.is_null() {
            /* index[i].name.len includes the terminating '\0' */

            ngx_string_macro::ngx_memcpy(
                name,
                (*index.offset(i as isize)).name.data,
                (*index.offset(i as isize)).name.len as usize,
            );

            path.len = name
                .offset((*index.offset(i as isize)).name.len as isize)
                .offset(-1)
                .offset_from(path.data) as u64;
        } else {
            e.ip = (*(*index.offset(i as isize)).values).elts as *mut u8;
            e.pos = name;

            while *(e.ip as *mut u64) != 0 {
                code = *(e.ip as *mut bindings::ngx_http_script_code_pt);
                code.expect("non-null function pointer")(
                    &mut e as *mut bindings::ngx_http_script_engine_t,
                );
            }
            if *name as i32 == '/' as i32 {
                uri.len = len.wrapping_sub(1);
                uri.data = name;
                // return bindings::NGX_DECLINED as bindings::ngx_int_t;
                return bindings::ngx_http_internal_redirect(r, &mut uri, &mut (*r).args);
            }

            path.len = e.pos.offset_from(path.data) as u64;
            *e.pos = '\u{0}' as i32 as u8;
        }

        ngx_log_debug!(
            bindings::NGX_LOG_DEBUG_HTTP,
            (*(*r).connection).log,
            0,
            b"open index \"%V\"\x00" as *const u8 as *const i8,
            &mut path as *mut bindings::ngx_str_t
        );

        ngx_memzero!(&mut of, mem::size_of::<bindings::ngx_open_file_info_t>());

        of.read_ahead = (*clcf).read_ahead;
        of.directio = (*clcf).directio;
        of.valid = (*clcf).open_file_cache_valid;
        of.min_uses = (*clcf).open_file_cache_min_uses;
        of.set_test_only(1);
        of.set_errors((*clcf).open_file_cache_errors as u32);
        of.set_events((*clcf).open_file_cache_events as u32);

        if bindings::ngx_http_set_disable_symlinks(r, clcf, &mut path, &mut of)
            != bindings::NGX_OK as isize
        {
            return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
        }
        if bindings::ngx_open_cached_file((*clcf).open_file_cache, &mut path, &mut of, (*r).pool)
            != bindings::NGX_OK as isize
        {
            if of.err == 0 {
                return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
            }

            ngx_log_debug!(
                bindings::NGX_LOG_DEBUG_HTTP,
                (*(*r).connection).log,
                of.err,
                b"%s \"%s\" failed\x00" as *const u8 as *const i8,
                of.failed,
                path.data
            );

            // if cfg!(NGX_HAVE_OPENAT) {
                if of.err == bindings::NGX_EMLINK as i32 || of.err == bindings::NGX_ELOOP as i32 {
                    return bindings::NGX_HTTP_FORBIDDEN as bindings::ngx_int_t;
                }
            // }

            if of.err == bindings::NGX_ENOTDIR as i32
                || of.err == bindings::NGX_ENAMETOOLONG as i32
                || of.err == bindings::NGX_EACCES as i32
            {
                return ngx_http_index_error(r, clcf, path.data, of.err);
            }

            if dir_tested == 0 {
                rc = ngx_http_index_test_dir(r, clcf, path.data, name.offset(-1));

                if rc != bindings::NGX_OK as isize {
                    return rc;
                }

                dir_tested = 1;
            }
            if of.err == bindings::NGX_ENOENT as i32 {
                i = i.wrapping_add(1);
            } else {
                ngx_log_error!(
                    bindings::NGX_LOG_CRIT as usize,
                    (*(*r).connection).log,
                    of.err,
                    b"%s \"%s\" failed\x00" as *const u8 as *const i8,
                    of.failed,
                    path.data
                );

                return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
            }
        } else {
            uri.len = (*r).uri.len.wrapping_add(len).wrapping_sub(1);
            if (*clcf).alias == 0 {
                uri.data = path.data.offset(root as isize);
            } else {
                uri.data = bindings::ngx_pnalloc((*r).pool, uri.len) as *mut u8;
                if uri.data.is_null() {
                    return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
                }
                let p: *mut u8 =
                    ngx_string_macro::ngx_cpymem(uri.data, (*r).uri.data, (*r).uri.len as usize);
                ngx_string_macro::ngx_memcpy(p, name, (len - 1) as usize);
            }
            // return bindings::NGX_DECLINED as bindings::ngx_int_t;
            return bindings::ngx_http_internal_redirect(r, &mut uri, &mut (*r).args);
        }
    }
    return bindings::NGX_DECLINED as bindings::ngx_int_t;
}

#[no_mangle]
pub unsafe extern "C" fn ngx_http_index_test_dir(
    mut r: *mut bindings::ngx_http_request_t,
    mut clcf: *mut bindings::ngx_http_core_loc_conf_t,
    mut path: *mut u8,
    mut last: *mut u8,
) -> bindings::ngx_int_t {
    let mut of = bindings::ngx_open_file_info_t {
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

    let mut c: bindings::u_char = *last;
    if c as i32 != '/' as i32 || path == last {
        /* "alias" without trailing slash */
        last = last.offset(1);
        c = *last;
    }

    *last = '\u{0}' as i32 as u8;

    let mut dir = bindings::ngx_str_t {
        len: last.offset_from(path) as u64,
        data: path,
    };

    ngx_log_debug!(
        bindings::NGX_LOG_DEBUG_HTTP,
        (*(*r).connection).log,
        0,
        b"http index check dir: \"%V\"\x00" as *const u8 as *const i8,
        &mut dir as *mut bindings::ngx_str_t
    );

    ngx_memzero!(&mut of, mem::size_of::<bindings::ngx_open_file_info_t>());

    of.set_test_dir(1);
    of.set_test_only(1);
    of.valid = (*clcf).open_file_cache_valid;
    of.set_errors((*clcf).open_file_cache_errors as u32);

    if bindings::ngx_http_set_disable_symlinks(r, clcf, &mut dir, &mut of)
        != bindings::NGX_OK as isize
    {
        return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
    }
    if bindings::ngx_open_cached_file((*clcf).open_file_cache, &mut dir, &mut of, (*r).pool)
        != bindings::NGX_OK as isize
    {
        if of.err != 0 {
            // if cfg!(NGX_HAVE_OPENAT) {
                if of.err == bindings::NGX_EMLINK as i32 || of.err == bindings::NGX_ELOOP as i32 {
                    return bindings::NGX_HTTP_FORBIDDEN as bindings::ngx_int_t;
                }
            // }
            if of.err == bindings::NGX_ENOENT as i32 {
                *last = c;
                return ngx_http_index_error(r, clcf, dir.data, bindings::NGX_ENOENT as i32);
            }

            if of.err == bindings::NGX_EACCES as i32 {
                *last = c;
                /*
                 * ngx_http_index_test_dir() is called after the first index
                 * file testing has returned an error distinct from NGX_EACCES.
                 * This means that directory searching is allowed.
                 */
                return bindings::NGX_OK as bindings::ngx_int_t;
            }

            ngx_log_error!(
                bindings::NGX_LOG_CRIT as usize,
                (*(*r).connection).log,
                of.err,
                b"%s \"%s\" failed\x00" as *const u8 as *const i8,
                of.failed,
                dir.data
            );
        }
        return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
    }
    *last = c;
    if of.is_dir() != 0 {
        return bindings::NGX_OK as bindings::ngx_int_t;
    }

    ngx_log_error!(
        bindings::NGX_LOG_ALERT as usize,
        (*(*r).connection).log,
        0,
        b"\"%s\" is not a directory\x00" as *const u8 as *const i8,
        dir.data
    );
    return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
}

#[no_mangle]
pub unsafe extern "C" fn ngx_http_index_error(
    mut r: *mut bindings::ngx_http_request_t,
    mut clcf: *mut bindings::ngx_http_core_loc_conf_t,
    mut file: *mut u8,
    mut err: bindings::ngx_err_t,
) -> bindings::ngx_int_t {
    if err == bindings::NGX_EACCES as i32 {
        ngx_log_error!(
            bindings::NGX_LOG_ERR as usize,
            (*(*r).connection).log,
            err,
            b"\"%s\" is forbidden\x00" as *const u8 as *const i8,
            file
        );
        return bindings::NGX_HTTP_FORBIDDEN as bindings::ngx_int_t;
    }
    if (*clcf).log_not_found != 0 {
        ngx_log_error!(
            bindings::NGX_LOG_ERR as usize,
            (*(*r).connection).log,
            err,
            b"\"%s\" is not found\x00" as *const u8 as *const i8,
            file
        );
    }
    return bindings::NGX_HTTP_NOT_FOUND as bindings::ngx_int_t;
}

#[no_mangle]
pub unsafe extern "C" fn ngx_http_index_create_loc_conf(
    mut cf: *mut bindings::ngx_conf_t,
) -> *mut libc::c_void {
    let mut conf: *mut ngx_http_index_loc_conf_t = bindings::ngx_palloc(
        (*cf).pool,
        mem::size_of::<ngx_http_index_loc_conf_t>() as u64,
    ) as *mut ngx_http_index_loc_conf_t;
    if conf.is_null() {
        return ptr::null_mut();
    }

    (*conf).indices = ptr::null_mut();
    (*conf).max_index_len = 0;
    return conf as *mut libc::c_void;
}

#[no_mangle]
pub unsafe extern "C" fn ngx_http_index_merge_loc_conf(
    mut cf: *mut bindings::ngx_conf_t,
    mut parent: *mut libc::c_void,
    mut child: *mut libc::c_void,
) -> *mut i8 {
    let mut prev: *mut ngx_http_index_loc_conf_t = parent as *mut ngx_http_index_loc_conf_t;
    let mut conf: *mut ngx_http_index_loc_conf_t = child as *mut ngx_http_index_loc_conf_t;

    if (*conf).indices.is_null() {
        (*conf).indices = (*prev).indices;
        (*conf).max_index_len = (*prev).max_index_len
    }
    if (*conf).indices.is_null() {
        (*conf).indices =
            bindings::ngx_array_create((*cf).pool, 1, mem::size_of::<ngx_http_index_t>() as u64);
        if (*conf).indices.is_null() {
            return NGX_CONF_ERROR!();
        }
        let index: *mut ngx_http_index_t =
            bindings::ngx_array_push((*conf).indices) as *mut ngx_http_index_t;
        if index.is_null() {
            return NGX_CONF_ERROR!();
        }
        (*index).name.len = ::std::mem::size_of_val(&NGX_HTTP_DEFAULT_INDEX) as libc::c_ulong;
        (*index).name.data = NGX_HTTP_DEFAULT_INDEX.as_ptr() as *mut u8;
        (*index).lengths = ptr::null_mut();
        (*index).values = ptr::null_mut();
        (*conf).max_index_len = ::std::mem::size_of_val(&NGX_HTTP_DEFAULT_INDEX) as libc::c_ulong;

        return NGX_CONF_OK!();
    }
    return NGX_CONF_OK!();
}

#[no_mangle]
pub unsafe extern "C" fn ngx_http_index_init(
    mut cf: *mut bindings::ngx_conf_t,
) -> bindings::ngx_int_t {
    let mut cmcf: *mut bindings::ngx_http_core_main_conf_t =
        *ngx_http_conf_get_module_main_conf!(cf, bindings::ngx_http_core_module)
            as *mut bindings::ngx_http_core_main_conf_t;
    // let mut h: *mut bindings::ngx_http_handler_pt = bindings::ngx_array_push(
    //     &mut (*(*cmcf)
    //         .phases
    //         .as_mut_ptr()
    //         .offset(bindings::ngx_http_phases::NGX_HTTP_CONTENT_PHASE as isize))
    //     .handlers,
    // ) as *mut bindings::ngx_http_handler_pt;
    let mut h: *mut bindings::ngx_http_handler_pt = bindings::ngx_array_push(
        &mut (*cmcf).phases[bindings::ngx_http_phases::NGX_HTTP_CONTENT_PHASE as usize].handlers,
    ) as *mut bindings::ngx_http_handler_pt;
    if h.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    *h = Some(ngx_http_index_handler);
    return bindings::NGX_OK as bindings::ngx_int_t;
}

/* TODO: warn about duplicate indices */
#[no_mangle]
pub unsafe extern "C" fn ngx_http_index_set_index(
    mut cf: *mut bindings::ngx_conf_t,
    mut cmd: *mut bindings::ngx_command_t,
    mut conf: *mut libc::c_void,
) -> *mut libc::c_char {
    let mut ilcf = conf as *mut ngx_http_index_loc_conf_t;
    let mut value = 0 as *mut bindings::ngx_str_t;
    let mut i: bindings::ngx_uint_t = 0;
    let mut n: bindings::ngx_uint_t = 0;
    let mut index = 0 as *mut ngx_http_index_t;
    let mut sc = bindings::ngx_http_script_compile_t {
        cf: 0 as *mut bindings::ngx_conf_t,
        source: 0 as *mut bindings::ngx_str_t,
        flushes: 0 as *mut *mut bindings::ngx_array_t,
        lengths: 0 as *mut *mut bindings::ngx_array_t,
        values: 0 as *mut *mut bindings::ngx_array_t,
        variables: 0,
        ncaptures: 0,
        captures_mask: 0,
        size: 0,
        main: 0 as *mut libc::c_void,
        _bitfield_align_1: [0; 0],
        _bitfield_1: bindings::ngx_http_script_compile_t::new_bitfield_1(0, 0, 0, 0, 0, 0, 0, 0),
        __bindgen_padding_0: [0; 7],
    };

    if (*ilcf).indices.is_null() {
        (*ilcf).indices =
            bindings::ngx_array_create((*cf).pool, 2, mem::size_of::<ngx_http_index_t>() as u64);
        if (*ilcf).indices.is_null() {
            return NGX_CONF_ERROR!();
        }
    }

    value = (*(*cf).args).elts as *mut bindings::ngx_str_t;

    i = 1;
    while i < (*(*cf).args).nelts {
        if *(*value.offset(i as isize)).data.offset(0) as i32 == '/' as i32
            && i != (*(*cf).args).nelts.wrapping_sub(1)
        {
            bindings::ngx_conf_log_error(
                bindings::NGX_LOG_WARN as bindings::ngx_uint_t,
                cf,
                0,
                b"only the last index in \"index\" directive should be absolute\x00" as *const u8
                    as *const i8,
            );
        }

        if (*value.offset(i as isize)).len == 0 {
            bindings::ngx_conf_log_error(
                bindings::NGX_LOG_EMERG as bindings::ngx_uint_t,
                cf,
                0,
                b"index \"%V\" in \"index\" directive is invalid\x00" as *const u8 as *const i8,
                &mut *value.offset(1) as *mut bindings::ngx_str_t,
            );
            return NGX_CONF_ERROR!();
        }

        index = bindings::ngx_array_push((*ilcf).indices) as *mut ngx_http_index_t;

        if index.is_null() {
            return NGX_CONF_ERROR!();
        }

        (*index).name.len = (*value.offset(i as isize)).len;
        (*index).name.data = (*value.offset(i as isize)).data;
        (*index).lengths = ptr::null_mut();
        (*index).values = ptr::null_mut();

        n = bindings::ngx_http_script_variables_count(&mut *value.offset(i as isize));

        if n == 0 {
            if (*ilcf).max_index_len < (*index).name.len {
                (*ilcf).max_index_len = (*index).name.len;
            }
            if !(*(*index).name.data.offset(0) as i32 == '/' as i32) {
                /* include the terminating '\0' to the length to use ngx_memcpy() */
                (*index).name.len = (*index).name.len.wrapping_add(1);
            }
        } else {
            ngx_memzero!(
                &mut sc,
                mem::size_of::<bindings::ngx_http_script_compile_t>()
            );

            sc.cf = cf;
            sc.source = &mut *value.offset(i as isize) as *mut bindings::ngx_str_t;
            sc.lengths = &mut (*index).lengths;
            sc.values = &mut (*index).values;
            sc.variables = n;
            sc.set_complete_lengths(1);
            sc.set_complete_values(1);

            if bindings::ngx_http_script_compile(&mut sc) != bindings::NGX_OK as isize {
                return NGX_CONF_ERROR!();
            }
        }
        i = i.wrapping_add(1);
    }
    return NGX_CONF_OK!();
}

pub unsafe extern "C" fn run_static_initializers() {
    ngx_http_index_commands = [
        {
            let mut init = bindings::ngx_command_t {
                name: ngx_string!("index\0"),
                type_: (bindings::NGX_HTTP_MAIN_CONF
                    | bindings::NGX_HTTP_SRV_CONF
                    | bindings::NGX_HTTP_LOC_CONF
                    | bindings::NGX_CONF_1MORE) as bindings::ngx_uint_t,
                set: Some(ngx_http_index_set_index),
                conf: offset_of!(bindings::ngx_http_conf_ctx_t, loc_conf),
                offset: 0,
                post: ptr::null_mut(),
            };
            init
        },
        {
            let mut init = ngx_null_command!();
            init
        },
    ];
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
