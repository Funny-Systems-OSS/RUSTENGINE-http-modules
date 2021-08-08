use crate::bindings;
use crate::core::ngx_array_macro;
use crate::core::ngx_module_macro;
use crate::core::ngx_string_macro;
use crate::event::ngx_event_timer_macro;
use crate::os::unix::ngx_files_macro;
use std::mem;
use std::ptr;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngx_http_log_op_s {
    pub len: bindings::size_t,
    pub getlen: ngx_http_log_op_getlen_pt,
    pub run: ngx_http_log_op_run_pt,
    pub data: usize,
}

#[allow(non_camel_case_types)]
pub type ngx_http_log_op_run_pt = Option<
    unsafe extern "C" fn(
        _: *mut bindings::ngx_http_request_t,
        _: *mut bindings::u_char,
        _: *mut ngx_http_log_op_t,
    ) -> *mut bindings::u_char,
>;

/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */
#[allow(non_camel_case_types)]
pub type ngx_http_log_op_t = ngx_http_log_op_s;

#[allow(non_camel_case_types)]
pub type ngx_http_log_op_getlen_pt = Option<
    unsafe extern "C" fn(_: *mut bindings::ngx_http_request_t, _: usize) -> bindings::size_t,
>;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngx_http_log_fmt_t {
    pub name: bindings::ngx_str_t,
    pub flushes: *mut bindings::ngx_array_t,
    pub ops: *mut bindings::ngx_array_t,
}

#[repr(C)]
#[derive(Copy, Clone)]

pub struct ngx_http_log_main_conf_t {
    pub formats: bindings::ngx_array_t,
    pub combined_used: bindings::ngx_uint_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngx_http_log_buf_t {
    pub start: *mut bindings::u_char,
    pub pos: *mut bindings::u_char,
    pub last: *mut bindings::u_char,
    pub event: *mut bindings::ngx_event_t,
    pub flush: bindings::ngx_msec_t,
    pub gzip: bindings::ngx_int_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngx_http_log_script_t {
    pub lengths: *mut bindings::ngx_array_t,
    pub values: *mut bindings::ngx_array_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngx_http_log_t {
    pub file: *mut bindings::ngx_open_file_t,
    pub script: *mut ngx_http_log_script_t,
    pub disk_full_time: bindings::time_t,
    pub error_log_time: bindings::time_t,
    pub syslog_peer: *mut bindings::ngx_syslog_peer_t,
    pub format: *mut ngx_http_log_fmt_t,
    pub filter: *mut bindings::ngx_http_complex_value_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngx_http_log_loc_conf_t {
    pub logs: *mut bindings::ngx_array_t,
    pub open_file_cache: *mut bindings::ngx_open_file_cache_t,
    pub open_file_cache_valid: bindings::time_t,
    pub open_file_cache_min_uses: bindings::ngx_uint_t,
    pub off: bindings::ngx_uint_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ngx_http_log_var_t {
    pub name: bindings::ngx_str_t,
    pub len: bindings::size_t,
    pub run: ngx_http_log_op_run_pt,
}

pub const NGX_HTTP_LOG_ESCAPE_DEFAULT: usize = 0;
pub const NGX_HTTP_LOG_ESCAPE_JSON: usize = 1;
pub const NGX_HTTP_LOG_ESCAPE_NONE: usize = 2;

// Initialized in run_static_initializers
#[allow(non_upper_case_globals)]
static mut ngx_http_log_commands: [bindings::ngx_command_t; 4] = [bindings::ngx_command_t {
    name: bindings::ngx_str_t {
        len: 0,
        data: ptr::null_mut(),
    },
    type_: 0,
    set: None,
    conf: 0,
    offset: 0,
    post: 0 as *mut libc::c_void,
}; 4];

#[allow(non_upper_case_globals)]
static mut ngx_http_log_module_ctx: bindings::ngx_http_module_t = {
    let init = bindings::ngx_http_module_t {
        preconfiguration: None,
        postconfiguration: Some(ngx_http_log_init),
        create_main_conf: Some(ngx_http_log_create_main_conf),
        init_main_conf: None,
        create_srv_conf: None,
        merge_srv_conf: None,
        create_loc_conf: Some(ngx_http_log_create_loc_conf),
        merge_loc_conf: Some(ngx_http_log_merge_loc_conf),
    };
    init
};

#[no_mangle]
pub static mut ngx_http_log_module: bindings::ngx_module_t = unsafe {
    {
        let init = bindings::ngx_module_t {
            ctx_index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as bindings::ngx_uint_t,
            index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as bindings::ngx_uint_t,
            name: ptr::null_mut(),
            spare0: 0,
            spare1: 0,
            version: bindings::nginx_version as bindings::ngx_uint_t,
            signature: ngx_module_macro::NGX_MODULE_SIGNATURE as *const u8 as *const i8,
            ctx: &ngx_http_log_module_ctx as *const bindings::ngx_http_module_t
                as *mut bindings::ngx_http_module_t as *mut libc::c_void,
            commands: ngx_http_log_commands.as_ptr() as *mut _,
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
// Initialized in run_static_initializers
#[allow(non_upper_case_globals)]
static mut ngx_http_access_log: bindings::ngx_str_t = bindings::ngx_str_t {
    len: 0,
    data: ptr::null_mut(),
};
// Initialized in run_static_initializers
#[allow(non_upper_case_globals)]
static mut ngx_http_combined_fmt: bindings::ngx_str_t = bindings::ngx_str_t {
    len: 0,
    data: ptr::null_mut(),
};
// Initialized in run_static_initializers
#[allow(non_upper_case_globals)]
static mut ngx_http_log_vars: [ngx_http_log_var_t; 10] = [ngx_http_log_var_t {
    name: bindings::ngx_str_t {
        len: 0,
        data: ptr::null_mut(),
    },
    len: 0,
    run: None,
}; 10];

unsafe extern "C" fn ngx_http_log_handler(
    mut r: *mut bindings::ngx_http_request_t,
) -> bindings::ngx_int_t {
    let mut line = 0 as *mut bindings::u_char;
    let mut p = 0 as *mut bindings::u_char;
    let mut len: bindings::size_t = 0;
    let mut size: bindings::size_t = 0;
    let mut n: bindings::ssize_t = 0;
    let mut val = bindings::ngx_str_t {
        len: 0,
        data: ptr::null_mut(),
    };
    let mut log = 0 as *mut ngx_http_log_t;
    let mut op = 0 as *mut ngx_http_log_op_t;
    let mut buffer = 0 as *mut ngx_http_log_buf_t;
    let mut lcf = 0 as *mut ngx_http_log_loc_conf_t;

    ngx_log_debug!(
        bindings::NGX_LOG_DEBUG_HTTP,
        (*(*r).connection).log,
        0,
        b"http log handler\x00" as *const u8 as *const i8
    );

    lcf = *ngx_http_get_module_loc_conf!(r, ngx_http_log_module) as *mut ngx_http_log_loc_conf_t;

    if (*lcf).off != 0 {
        return bindings::NGX_OK as bindings::ngx_int_t;
    }

    log = (*(*lcf).logs).elts as *mut ngx_http_log_t;
    let mut alloc_line: bool = false;
    for l in 0..(*(*lcf).logs).nelts {
        if !(*log.offset(l as isize)).filter.is_null() {
            if bindings::ngx_http_complex_value(r, (*log.offset(l as isize)).filter, &mut val)
                != bindings::NGX_OK as isize
            {
                return bindings::NGX_ERROR as bindings::ngx_int_t;
            }
            if val.len == 0 as libc::c_int as libc::c_ulong
                || (val.len == 1 && *val.data.offset(0) == '0' as u8)
            {
                continue;
            }
        }

        if ngx_time!() == (*log.offset(l as isize)).disk_full_time {
            /*
             * on FreeBSD writing to a full filesystem with enabled softupdates
             * may block process for much longer time than writing to non-full
             * filesystem, so we skip writing to a log for one second
             */
            continue;
        }
        bindings::ngx_http_script_flush_no_cacheable_variables(
            r,
            (*(*log.offset(l as isize)).format).flushes,
        );

        len = 0;
        op = (*(*(*log.offset(l as isize)).format).ops).elts as *mut ngx_http_log_op_t;

        for i in 0..(*(*(*log.offset(l as isize)).format).ops).nelts {
            if (*op.offset(i as isize)).len == 0 {
                len = len.wrapping_add((*op.offset(i as isize))
                    .getlen
                    .expect("non-null function pointer")(
                    r, (*op.offset(i as isize)).data
                ) as bindings::size_t);
            } else {
                len = len.wrapping_add((*op.offset(i as isize)).len as bindings::size_t);
            }
        }

        if !(*log.offset(l as isize)).syslog_peer.is_null() {
            /* length of syslog's PRI and HEADER message parts */
            len = (len as libc::c_ulong).wrapping_add(
                (::std::mem::size_of::<[i8; 22]>() as libc::c_ulong) // sizeof("<255>Jan 01 00:00:00 ")
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    .wrapping_add((*bindings::ngx_cycle).hostname.len)
                    .wrapping_add(1 as libc::c_int as libc::c_ulong)
                    .wrapping_add((*(*log.offset(l as isize)).syslog_peer).tag.len)
                    .wrapping_add(2 as libc::c_int as libc::c_ulong),
            ) as bindings::size_t;

            alloc_line = true;
        } else {
            len = (len as libc::c_ulong).wrapping_add(bindings::NGX_LINEFEED_SIZE as libc::c_ulong)
                as bindings::size_t;
            buffer = if !(*log.offset(l as isize)).file.is_null() {
                (*(*log.offset(l as isize)).file).data
            } else {
                ptr::null_mut()
            } as *mut ngx_http_log_buf_t;
            if !buffer.is_null() {
                if len
                    > (*buffer).last.offset_from((*buffer).pos) as libc::c_long as bindings::size_t
                {
                    ngx_http_log_write(
                        r,
                        &mut *log.offset(l as isize),
                        (*buffer).start,
                        (*buffer).pos.offset_from((*buffer).start) as libc::c_long
                            as bindings::size_t,
                    );
                    (*buffer).pos = (*buffer).start;
                }
                if len
                    <= (*buffer).last.offset_from((*buffer).pos) as libc::c_long as bindings::size_t
                {
                    p = (*buffer).pos;
                    if !(*buffer).event.is_null() && p == (*buffer).start {
                        ngx_event_timer_macro::ngx_event_add_timer(
                            (*buffer).event,
                            (*buffer).flush,
                        );
                    }
                    for i in 0..(*(*(*log.offset(l as isize)).format).ops).nelts {
                        p = (*op.offset(i as isize))
                            .run
                            .expect("non-null function pointer")(
                            r, p, &mut *op.offset(i as isize)
                        );
                    }

                    ngx_linefeed!(p);
                    (*buffer).pos = p;

                    continue;
                } else {
                    if !(*buffer).event.is_null()
                        && (*(*buffer).event).timer_set() as libc::c_int != 0
                    {
                        ngx_event_timer_macro::ngx_event_del_timer((*buffer).event);
                    }
                    alloc_line = true;
                }
            } else {
                alloc_line = true;
            }

            match alloc_line {
                true => {
                    line = bindings::ngx_pnalloc((*r).pool, len as u64) as *mut bindings::u_char;
                    if line.is_null() {
                        return bindings::NGX_ERROR as bindings::ngx_int_t;
                    }
                    p = line;
                    if !(*log.offset(l as isize)).syslog_peer.is_null() {
                        p = bindings::ngx_syslog_add_header(
                            (*log.offset(l as isize)).syslog_peer,
                            line,
                        )
                    }
                    for i in 0..(*(*(*log.offset(l as isize)).format).ops).nelts {
                        p = (*op.offset(i as isize))
                            .run
                            .expect("non-null function pointer")(
                            r, p, &mut *op.offset(i as isize)
                        );
                    }
                    if !(*log.offset(l as isize)).syslog_peer.is_null() {
                        size = p.offset_from(line) as libc::c_long as bindings::size_t;
                        n = bindings::ngx_syslog_send(
                            (*log.offset(l as isize)).syslog_peer,
                            line,
                            size,
                        );
                        if n < 0 {
                            ngx_log_error!(
                                bindings::NGX_LOG_WARN as usize,
                                (*(*r).connection).log,
                                0 as libc::c_int,
                                b"send() to syslog failed\x00" as *const u8 as *const i8
                            );
                        } else if n != size as bindings::ssize_t {
                            ngx_log_error!(
                                bindings::NGX_LOG_WARN as usize,
                                (*(*r).connection).log,
                                0 as libc::c_int,
                                b"send() to syslog has written only %z of %uz\x00" as *const u8
                                    as *const i8,
                                n,
                                size
                            );
                        }
                    } else {
                        ngx_linefeed!(p);
                        ngx_http_log_write(
                            r,
                            &mut *log.offset(l as isize),
                            line,
                            p.offset_from(line) as libc::c_long as bindings::size_t,
                        );
                    }
                }
                _ => {}
            }
        }
    }
    return bindings::NGX_OK as bindings::ngx_int_t;
}

unsafe extern "C" fn ngx_http_log_write(
    mut r: *mut bindings::ngx_http_request_t,
    mut log: *mut ngx_http_log_t,
    mut buf: *mut bindings::u_char,
    mut len: bindings::size_t,
) {
    let mut name = 0 as *mut bindings::u_char;
    let mut now: bindings::time_t = 0;
    let mut n: bindings::ssize_t = 0;
    let mut err: bindings::ngx_err_t = 0;

    // std::thread::sleep(std::time::Duration::from_millis(4000));

    if (*log).script.is_null() {
        name = (*(*log).file).name.data;
        #[cfg(all(NGX_ZLIB))]
        {
            let buffer: *mut ngx_http_log_buf_t = (*(*log).file).data as *mut ngx_http_log_buf_t;
            if !buffer.is_null() && (*buffer).gzip != 0 {
                n = ngx_http_log_gzip(
                    (*(*log).file).fd,
                    buf,
                    len,
                    (*buffer).gzip,
                    (*(*r).connection).log,
                );
            } else {
                n = ngx_files_macro::ngx_write_fd((*(*log).file).fd, buf as *mut libc::c_void, len)
                    as bindings::ssize_t;
            }
        }
        #[cfg(not(NGX_ZLIB))]
        {
            n = ngx_files_macro::ngx_write_fd((*(*log).file).fd, buf as *mut libc::c_void, len)
                as bindings::ssize_t;
        }
    } else {
        name = ptr::null_mut();
        n = ngx_http_log_script_write(r, (*log).script, &mut name, buf, len);
    }
    if n == len as bindings::ssize_t {
        return;
    }

    now = ngx_time!();
    if n == -1 {
        err = ngx_errno!();
        if err == bindings::NGX_ENOSPC as i32 {
            (*log).disk_full_time = now;
        }
        if now - (*log).error_log_time > 59 {
            ngx_log_error!(
                bindings::NGX_LOG_ALERT as usize,
                (*(*r).connection).log,
                err,
                b"write() to \"%s\" failed\x00" as *const u8 as *const i8,
                name
            );
            (*log).error_log_time = now;
        }
        return;
    }
    if now - (*log).error_log_time > 59 {
        ngx_log_error!(
            bindings::NGX_LOG_ALERT as usize,
            (*(*r).connection).log,
            0 as libc::c_int,
            b"write() to \"%s\" was incomplete: %z of %uz\x00" as *const u8 as *const i8,
            name,
            n,
            len
        );
        (*log).error_log_time = now;
    };
}

unsafe extern "C" fn ngx_http_log_script_write(
    mut r: *mut bindings::ngx_http_request_t,
    mut script: *mut ngx_http_log_script_t,
    mut name: *mut *mut bindings::u_char,
    mut buf: *mut bindings::u_char,
    mut len: bindings::size_t,
) -> bindings::ssize_t {
    let mut root: bindings::size_t = 0;
    let mut n: bindings::ssize_t = 0;
    let mut log = bindings::ngx_str_t {
        len: 0,
        data: 0 as *const bindings::u_char as *mut bindings::u_char,
    };
    let mut path = bindings::ngx_str_t {
        len: 0,
        data: 0 as *const bindings::u_char as *mut bindings::u_char,
    };
    let mut of = bindings::ngx_open_file_info_t {
        fd: 0,
        uniq: 0,
        mtime: 0,
        size: 0,
        fs_size: 0,
        directio: 0,
        read_ahead: 0,
        err: 0,
        failed: 0 as *mut i8,
        valid: 0,
        min_uses: 0,
        disable_symlinks_from: 0,
        _bitfield_align_1: [0; 0],
        _bitfield_1: bindings::ngx_open_file_info_t::new_bitfield_1(
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ),
        __bindgen_padding_0: [0; 3],
    };
    let mut llcf: *mut ngx_http_log_loc_conf_t = ptr::null_mut();
    let mut clcf: *mut bindings::ngx_http_core_loc_conf_t = ptr::null_mut();

    clcf = *ngx_http_get_module_loc_conf!(r, bindings::ngx_http_core_module)
        as *mut bindings::ngx_http_core_loc_conf_t;

    if (*r).root_tested() == 0 {
        /* test root directory existence */
        if bindings::ngx_http_map_uri_to_path(r, &mut path, &mut root, 0).is_null() {
            /* simulate successful logging */
            return len as bindings::ssize_t;
        }

        *path.data.offset(root as isize) = '\u{0}' as i32 as bindings::u_char;

        of.valid = (*clcf).open_file_cache_valid;
        of.min_uses = (*clcf).open_file_cache_min_uses;

        of.set_test_dir(1);
        of.set_test_only(1);

        of.set_errors((*clcf).open_file_cache_errors as u32);
        of.set_events((*clcf).open_file_cache_events as u32);

        if bindings::ngx_http_set_disable_symlinks(r, clcf, &mut path, &mut of)
            != bindings::NGX_OK as isize
        {
            /* simulate successful logging */
            return len as bindings::ssize_t;
        }

        if bindings::ngx_open_cached_file((*clcf).open_file_cache, &mut path, &mut of, (*r).pool)
            != bindings::NGX_OK as isize
        {
            if of.err == 0 as libc::c_int {
                /* simulate successful logging */
                return len as bindings::ssize_t;
            }
            ngx_log_error!(
                bindings::NGX_LOG_ERR as usize,
                (*(*r).connection).log,
                of.err,
                b"testing \"%s\" existence failed\x00" as *const u8 as *const i8,
                path.data
            );
            /* simulate successful logging */
            return len as bindings::ssize_t;
        }
        if of.is_dir() == 0 {
            ngx_log_error!(
                bindings::NGX_LOG_ERR as usize,
                (*(*r).connection).log,
                20 as libc::c_int,
                b"testing \"%s\" existence failed\x00" as *const u8 as *const i8,
                path.data
            );
            /* simulate successful logging */
            return len as bindings::ssize_t;
        }
    }
    if bindings::ngx_http_script_run(
        r,
        &mut log,
        (*(*script).lengths).elts,
        1,
        (*(*script).values).elts,
    )
    .is_null()
    {
        /* simulate successful logging */
        return len as bindings::ssize_t;
    }

    *log.data.offset(log.len.wrapping_sub(1) as isize) = '\u{0}' as i32 as bindings::u_char;
    *name = log.data;

    ngx_log_debug!(
        bindings::NGX_LOG_DEBUG_HTTP,
        (*(*r).connection).log,
        0,
        b"http log \"%s\"\x00" as *const u8 as *const i8,
        log.data
    );

    llcf = *ngx_http_get_module_loc_conf!(r, ngx_http_log_module) as *mut ngx_http_log_loc_conf_t;

    ngx_memzero!(&mut of, mem::size_of::<bindings::ngx_open_file_info_t>());

    of.set_log(1);
    of.valid = (*llcf).open_file_cache_valid;
    of.min_uses = (*llcf).open_file_cache_min_uses;
    of.directio = bindings::NGX_OPEN_FILE_DIRECTIO_OFF as bindings::off_t;
    if bindings::ngx_http_set_disable_symlinks(r, clcf, &mut log, &mut of)
        != bindings::NGX_OK as isize
    {
        /* simulate successful logging */
        return len as bindings::ssize_t;
    }

    if bindings::ngx_open_cached_file((*llcf).open_file_cache, &mut log, &mut of, (*r).pool)
        != bindings::NGX_OK as isize
    {
        if of.err == 0 {
            /* simulate successful logging */
            return len as bindings::ssize_t;
        }

        ngx_log_error!(
            bindings::NGX_LOG_CRIT as usize,
            (*(*r).connection).log,
            ngx_errno!(),
            b"%s \"%s\" failed\x00" as *const u8 as *const i8,
            of.failed,
            log.data
        );
        /* simulate successful logging */
        return len as bindings::ssize_t;
    }

    ngx_log_debug!(
        bindings::NGX_LOG_DEBUG_HTTP,
        (*(*r).connection).log,
        0,
        b"http log #%d\x00" as *const u8 as *const i8,
        of.fd
    );
    n = ngx_files_macro::ngx_write_fd(of.fd, buf as *mut libc::c_void, len);
    return n;
}

// pass Zlib
#[cfg(all(NGX_ZLIB))]
unsafe extern "C" fn ngx_http_log_gzip(
    fd: bindings::ngx_fd_t,
    buf: *mut bindings::u_char,
    len: bindings::size_t,
    level: bindings::ngx_int_t,
    log: *mut bindings::ngx_log_t,
) -> bindings::ssize_t;

// pass Zlib
#[cfg(all(NGX_ZLIB))]
unsafe extern "C" fn ngx_http_log_gzip_alloc(
    opaque: *mut libc::c_void,
    items: bindings::u_int,
    size: bindings::u_int,
);

// pass Zlib
#[cfg(all(NGX_ZLIB))]
unsafe extern "C" fn ngx_http_log_gzip_free(opaque: *mut libc::c_void, address: *mut libc::c_void);

unsafe extern "C" fn ngx_http_log_flush(
    mut file: *mut bindings::ngx_open_file_t,
    mut log: *mut bindings::ngx_log_t,
) {
    let mut len: bindings::size_t = 0;
    let mut n: bindings::ssize_t = 0;
    let mut buffer = 0 as *mut ngx_http_log_buf_t;

    buffer = (*file).data as *mut ngx_http_log_buf_t;
    len = (*buffer).pos.offset_from((*buffer).start) as u64;

    if len == 0 {
        return;
    }

    #[cfg(all(NGX_ZLIB))]
    {
        if (*buffer).gzip != 0 {
            n = ngx_http_log_gzip((*file).fd, (*buffer).start, len, (*buffer).gzip, log);
        } else {
            n = ngx_files_macro::ngx_write_fd(
                (*file).fd,
                (*buffer).start as *mut libc::c_void,
                len,
            );
        }
    }
    #[cfg(not(NGX_ZLIB))]
    {
        n = ngx_files_macro::ngx_write_fd((*file).fd, (*buffer).start as *mut libc::c_void, len);
    }
    if n == -1 {
        ngx_log_error!(
            bindings::NGX_LOG_ALERT as usize,
            log,
            ngx_errno!(),
            b"write() to \"%s\" failed\x00" as *const u8 as *const i8,
            (*file).name.data
        );
    } else if n as bindings::size_t != len {
        ngx_log_error!(
            bindings::NGX_LOG_ALERT as usize,
            log,
            0,
            b"write() to \"%s\" was incomplete: %z of %uz\x00" as *const u8 as *const i8,
            (*file).name.data,
            n,
            len
        );
    }
    (*buffer).pos = (*buffer).start;
    if !(*buffer).event.is_null() && (*(*buffer).event).timer_set() != 0 {
        ngx_event_timer_macro::ngx_event_del_timer((*buffer).event);
    };
}

unsafe extern "C" fn ngx_http_log_flush_handler(mut ev: *mut bindings::ngx_event_t) {
    ngx_log_debug!(
        bindings::NGX_LOG_DEBUG_EVENT,
        (*ev).log,
        0,
        b"http log buffer flush handler\x00" as *const u8 as *const i8
    );
    ngx_http_log_flush((*ev).data as *mut bindings::ngx_open_file_t, (*ev).log);
}

unsafe extern "C" fn ngx_http_log_copy_short(
    mut r: *mut bindings::ngx_http_request_t,
    mut buf: *mut bindings::u_char,
    mut op: *mut ngx_http_log_op_t,
) -> *mut bindings::u_char {
    let mut len: bindings::size_t = 0;
    let mut data: usize = 0;

    len = (*op).len;
    data = (*op).data;

    while len != 0 {
        len = len.wrapping_sub(1);
        *buf = (data & 0xff) as bindings::u_char;
        buf = buf.offset(1);
        data >>= 8;
    }
    return buf;
}

unsafe extern "C" fn ngx_http_log_copy_long(
    mut r: *mut bindings::ngx_http_request_t,
    mut buf: *mut bindings::u_char,
    mut op: *mut ngx_http_log_op_t,
) -> *mut bindings::u_char {
    return ngx_string_macro::ngx_cpymem(
        buf,
        (*op).data as *mut bindings::u_char,
        (*op).len as usize,
    );
}

unsafe extern "C" fn ngx_http_log_pipe(
    mut r: *mut bindings::ngx_http_request_t,
    mut buf: *mut bindings::u_char,
    mut op: *mut ngx_http_log_op_t,
) -> *mut bindings::u_char {
    if (*r).pipeline() != 0 {
        *buf = 'p' as i32 as bindings::u_char;
    } else {
        *buf = '.' as i32 as bindings::u_char;
    }
    return buf.offset(1);
}

unsafe extern "C" fn ngx_http_log_time(
    mut r: *mut bindings::ngx_http_request_t,
    mut buf: *mut bindings::u_char,
    mut op: *mut ngx_http_log_op_t,
) -> *mut bindings::u_char {
    return ngx_string_macro::ngx_cpymem(
        buf,
        bindings::ngx_cached_http_log_time.data,
        bindings::ngx_cached_http_log_time.len as usize,
    );
}

unsafe extern "C" fn ngx_http_log_iso8601(
    mut r: *mut bindings::ngx_http_request_t,
    mut buf: *mut bindings::u_char,
    mut op: *mut ngx_http_log_op_t,
) -> *mut bindings::u_char {
    return ngx_string_macro::ngx_cpymem(
        buf,
        bindings::ngx_cached_http_log_iso8601.data,
        bindings::ngx_cached_http_log_iso8601.len as usize,
    );
}

unsafe extern "C" fn ngx_http_log_msec(
    mut r: *mut bindings::ngx_http_request_t,
    mut buf: *mut bindings::u_char,
    mut op: *mut ngx_http_log_op_t,
) -> *mut bindings::u_char {
    let mut tp: *mut bindings::ngx_time_t = ptr::null_mut();
    tp = ngx_timeofday!();
    return bindings::ngx_sprintf(
        buf,
        b"%T.%03M\x00" as *const u8 as *const i8,
        (*tp).sec,
        (*tp).msec,
    );
}

unsafe extern "C" fn ngx_http_log_request_time(
    mut r: *mut bindings::ngx_http_request_t,
    mut buf: *mut bindings::u_char,
    mut op: *mut ngx_http_log_op_t,
) -> *mut bindings::u_char {
    let mut tp: *mut bindings::ngx_time_t = ptr::null_mut();
    let mut ms: bindings::ngx_msec_int_t = 0;

    tp = ngx_timeofday!();

    ms = ((((*tp).sec - (*r).start_sec) * 1000 as libc::c_int as libc::c_long) as libc::c_ulong)
        .wrapping_add((*tp).msec.wrapping_sub((*r).start_msec) as u64)
        as bindings::ngx_msec_int_t;

    ms = ngx_max!(ms, 0);
    return bindings::ngx_sprintf(
        buf,
        b"%T.%03M\x00" as *const u8 as *const i8,
        ms / 1000 as isize,
        ms % 1000 as isize,
    );
}

unsafe extern "C" fn ngx_http_log_status(
    mut r: *mut bindings::ngx_http_request_t,
    mut buf: *mut bindings::u_char,
    mut op: *mut ngx_http_log_op_t,
) -> *mut bindings::u_char {
    let mut status: bindings::ngx_uint_t = 0;

    if (*r).err_status != 0 {
        status = (*r).err_status;
    } else if (*r).headers_out.status != 0 {
        status = (*r).headers_out.status;
    } else if (*r).http_version == bindings::NGX_HTTP_VERSION_9 as usize {
        status = 9;
    } else {
        status = 0;
    }

    return bindings::ngx_sprintf(buf, b"%03ui\x00" as *const u8 as *const i8, status);
}

unsafe extern "C" fn ngx_http_log_bytes_sent(
    mut r: *mut bindings::ngx_http_request_t,
    mut buf: *mut bindings::u_char,
    mut op: *mut ngx_http_log_op_t,
) -> *mut bindings::u_char {
    return bindings::ngx_sprintf(
        buf,
        b"%O\x00" as *const u8 as *const i8,
        (*(*r).connection).sent,
    );
}
/*
 * although there is a real $body_bytes_sent variable,
 * this log operation code function is more optimized for logging
 */
unsafe extern "C" fn ngx_http_log_body_bytes_sent(
    mut r: *mut bindings::ngx_http_request_t,
    mut buf: *mut bindings::u_char,
    mut op: *mut ngx_http_log_op_t,
) -> *mut bindings::u_char {
    let mut length: bindings::off_t = 0;

    length = ((*(*r).connection).sent).wrapping_sub((*r).header_size as i64) as bindings::off_t;

    if length > 0 {
        return bindings::ngx_sprintf(buf, b"%O\x00" as *const u8 as *const i8, length);
    }
    *buf = '0' as i32 as bindings::u_char;
    return buf.offset(1);
}

unsafe extern "C" fn ngx_http_log_request_length(
    mut r: *mut bindings::ngx_http_request_t,
    mut buf: *mut bindings::u_char,
    mut op: *mut ngx_http_log_op_t,
) -> *mut bindings::u_char {
    return bindings::ngx_sprintf(
        buf,
        b"%O\x00" as *const u8 as *const i8,
        (*r).request_length,
    );
}

unsafe extern "C" fn ngx_http_log_variable_compile(
    mut cf: *mut bindings::ngx_conf_t,
    mut op: *mut ngx_http_log_op_t,
    mut value: *mut bindings::ngx_str_t,
    mut escape: bindings::ngx_uint_t,
) -> bindings::ngx_int_t {
    let mut index: bindings::ngx_int_t = 0;
    index = bindings::ngx_http_get_variable_index(cf, value);
    if index == bindings::NGX_ERROR as isize {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    (*op).len = 0;
    match escape {
        NGX_HTTP_LOG_ESCAPE_JSON => {
            (*op).getlen = Some(ngx_http_log_json_variable_getlen);
            (*op).run = Some(ngx_http_log_json_variable);
        }
        NGX_HTTP_LOG_ESCAPE_NONE => {
            (*op).getlen = Some(ngx_http_log_unescaped_variable_getlen);
            (*op).run = Some(ngx_http_log_unescaped_variable)
        }
        _ => {
            /* NGX_HTTP_LOG_ESCAPE_DEFAULT */
            (*op).getlen = Some(ngx_http_log_variable_getlen);
            (*op).run = Some(ngx_http_log_variable)
        }
    }
    (*op).data = index as usize;
    return bindings::NGX_OK as bindings::ngx_int_t;
}

unsafe extern "C" fn ngx_http_log_variable_getlen(
    mut r: *mut bindings::ngx_http_request_t,
    mut data: usize,
) -> bindings::size_t {
    let mut len: usize = 0;
    let mut value = 0 as *mut bindings::ngx_http_variable_value_t;

    value = bindings::ngx_http_get_indexed_variable(r, data);
    if value.is_null() || (*value).not_found() != 0 {
        return 1;
    }
    len = ngx_http_log_escape(
        ptr::null_mut(),
        (*value).data,
        (*value).len() as bindings::size_t,
    );

    (*value).set_escape(if len != 0 { 1 } else { 0 });
    return ((*value).len() as libc::c_ulong).wrapping_add(len.wrapping_mul(3) as u64);
}

unsafe extern "C" fn ngx_http_log_variable(
    mut r: *mut bindings::ngx_http_request_t,
    mut buf: *mut bindings::u_char,
    mut op: *mut ngx_http_log_op_t,
) -> *mut bindings::u_char {
    let mut value: *mut bindings::ngx_http_variable_value_t = ptr::null_mut();

    value = bindings::ngx_http_get_indexed_variable(r, (*op).data);

    if value.is_null() || (*value).not_found() != 0 {
        *buf = '-' as i32 as bindings::u_char;
        return buf.offset(1);
    }
    if (*value).escape() == 0 {
        return ngx_string_macro::ngx_cpymem(buf, (*value).data, (*value).len() as usize);
    } else {
        return ngx_http_log_escape(buf, (*value).data, (*value).len() as bindings::size_t)
            as *mut bindings::u_char;
    };
}

unsafe extern "C" fn ngx_http_log_escape(
    mut dst: *mut bindings::u_char,
    mut src: *mut bindings::u_char,
    mut size: bindings::size_t,
) -> usize {
    let mut n: bindings::ngx_uint_t = 0;
    static mut hex: &[bindings::u_char; 17] = b"0123456789ABCDEF\x00";
    static mut escape: [u32; 8] = [
        0xffffffff as u32,
        /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0x00000004 as u32,
        /* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
        /* 0000 0000 0000 0000  0000 0000 0000 0100 */
        0x10000000 as u32,
        /* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
        /* 0001 0000 0000 0000  0000 0000 0000 0000 */
        0x80000000 as u32,
        /*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
        /* 1000 0000 0000 0000  0000 0000 0000 0000 */
        0xffffffff as u32,
        /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff as u32,
        /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff as u32,
        /* 1111 1111 1111 1111  1111 1111 1111 1111 */
        0xffffffff as u32,
        /* 1111 1111 1111 1111  1111 1111 1111 1111 */
    ];
    if dst.is_null() {
        /* find the number of the characters to be escaped */
        n = 0;
        while size != 0 {
            if escape[(*src >> 5) as usize] & (1 << (*src & 0x1f)) != 0 {
                n = n.wrapping_add(1);
            }
            src = src.offset(1);
            size = size.wrapping_sub(1);
        }
        return n as usize;
    }
    while size != 0 {
        if escape[(*src >> 5) as usize] & (1 << (*src & 0x1f)) != 0 {
            *dst = '\\' as i32 as bindings::u_char;
            dst = dst.offset(1);

            *dst = 'x' as i32 as bindings::u_char;
            dst = dst.offset(1);

            *dst = hex[(*src >> 4) as usize];
            dst = dst.offset(1);

            *dst = hex[(*src & 0xf) as usize];
            dst = dst.offset(1);

            src = src.offset(1)
        } else {
            *dst = *src;
            src = src.offset(1);
            dst = dst.offset(1);
        }
        size = size.wrapping_sub(1)
    }
    return dst as usize;
}

unsafe extern "C" fn ngx_http_log_json_variable_getlen(
    mut r: *mut bindings::ngx_http_request_t,
    mut data: usize,
) -> bindings::size_t {
    let mut len: usize = 0;
    let mut value: *mut bindings::ngx_http_variable_value_t = ptr::null_mut();
    value = bindings::ngx_http_get_indexed_variable(r, data);
    if value.is_null() || (*value).not_found() != 0 {
        return 0;
    }
    len = bindings::ngx_escape_json(
        ptr::null_mut(),
        (*value).data,
        (*value).len() as bindings::size_t,
    );
    (*value).set_escape(if len != 0 { 1 } else { 0 });
    return ((*value).len() as libc::c_ulong).wrapping_add(len as u64);
}

unsafe extern "C" fn ngx_http_log_json_variable(
    mut r: *mut bindings::ngx_http_request_t,
    mut buf: *mut bindings::u_char,
    mut op: *mut ngx_http_log_op_t,
) -> *mut bindings::u_char {
    let mut value: *mut bindings::ngx_http_variable_value_t = ptr::null_mut();
    value = bindings::ngx_http_get_indexed_variable(r, (*op).data);
    if value.is_null() || (*value).not_found() != 0 {
        return buf;
    }
    if (*value).escape() == 0 {
        return ngx_string_macro::ngx_cpymem(buf, (*value).data, (*value).len() as usize);
    } else {
        return bindings::ngx_escape_json(buf, (*value).data, (*value).len() as bindings::size_t)
            as *mut bindings::u_char;
    };
}

unsafe extern "C" fn ngx_http_log_unescaped_variable_getlen(
    mut r: *mut bindings::ngx_http_request_t,
    mut data: usize,
) -> bindings::size_t {
    let mut value: *mut bindings::ngx_http_variable_value_t = ptr::null_mut();
    value = bindings::ngx_http_get_indexed_variable(r, data);
    if value.is_null() || (*value).not_found() as libc::c_int != 0 {
        return 0;
    }
    (*value).set_escape(0);
    return (*value).len() as bindings::size_t;
}

unsafe extern "C" fn ngx_http_log_unescaped_variable(
    mut r: *mut bindings::ngx_http_request_t,
    mut buf: *mut bindings::u_char,
    mut op: *mut ngx_http_log_op_t,
) -> *mut bindings::u_char {
    let mut value: *mut bindings::ngx_http_variable_value_t = ptr::null_mut();
    value = bindings::ngx_http_get_indexed_variable(r, (*op).data);
    if value.is_null() || (*value).not_found() != 0 {
        return buf;
    }
    return ngx_string_macro::ngx_cpymem(buf, (*value).data, (*value).len() as usize);
}

unsafe extern "C" fn ngx_http_log_create_main_conf(
    mut cf: *mut bindings::ngx_conf_t,
) -> *mut libc::c_void {
    let mut conf: *mut ngx_http_log_main_conf_t = ptr::null_mut();
    let mut fmt: *mut ngx_http_log_fmt_t = ptr::null_mut();

    conf = bindings::ngx_pcalloc(
        (*cf).pool,
        mem::size_of::<ngx_http_log_main_conf_t>() as u64,
    ) as *mut ngx_http_log_main_conf_t;
    if conf.is_null() {
        return ptr::null_mut();
    }

    if ngx_array_macro::ngx_array_init(
        &mut (*conf).formats,
        (*cf).pool,
        4,
        mem::size_of::<ngx_http_log_fmt_t>() as u64,
    ) != bindings::NGX_OK as isize
    {
        return ptr::null_mut();
    }

    fmt = bindings::ngx_array_push(&mut (*conf).formats) as *mut ngx_http_log_fmt_t;
    if fmt.is_null() {
        return ptr::null_mut();
    }

    ngx_str_set!(&mut (*fmt).name, b"combined\0");

    (*fmt).flushes = ptr::null_mut();

    (*fmt).ops =
        bindings::ngx_array_create((*cf).pool, 16, mem::size_of::<ngx_http_log_op_t>() as u64);
    if (*fmt).ops.is_null() {
        return ptr::null_mut();
    }
    return conf as *mut libc::c_void;
}

unsafe extern "C" fn ngx_http_log_create_loc_conf(
    mut cf: *mut bindings::ngx_conf_t,
) -> *mut libc::c_void {
    let mut conf = 0 as *mut ngx_http_log_loc_conf_t;
    conf = bindings::ngx_pcalloc((*cf).pool, mem::size_of::<ngx_http_log_loc_conf_t>() as u64)
        as *mut ngx_http_log_loc_conf_t;
    if conf.is_null() {
        return ptr::null_mut();
    }
    (*conf).open_file_cache = NGX_CONF_UNSET_PTR!() as *mut bindings::ngx_open_file_cache_t;
    return conf as *mut libc::c_void;
}

unsafe extern "C" fn ngx_http_log_merge_loc_conf(
    mut cf: *mut bindings::ngx_conf_t,
    mut parent: *mut libc::c_void,
    mut child: *mut libc::c_void,
) -> *mut i8 {
    let mut prev = parent as *mut ngx_http_log_loc_conf_t;
    let mut conf = child as *mut ngx_http_log_loc_conf_t;

    let mut log: *mut ngx_http_log_t = ptr::null_mut();
    let mut fmt: *mut ngx_http_log_fmt_t = ptr::null_mut();
    let mut lmcf: *mut ngx_http_log_main_conf_t = ptr::null_mut();

    if (*conf).open_file_cache == NGX_CONF_UNSET_PTR!() as *mut bindings::ngx_open_file_cache_t {
        (*conf).open_file_cache = (*prev).open_file_cache;
        (*conf).open_file_cache_valid = (*prev).open_file_cache_valid;
        (*conf).open_file_cache_min_uses = (*prev).open_file_cache_min_uses;

        if (*conf).open_file_cache == NGX_CONF_UNSET_PTR!() as *mut bindings::ngx_open_file_cache_t
        {
            (*conf).open_file_cache = ptr::null_mut();
        }
    }
    if !(*conf).logs.is_null() || (*conf).off != 0 {
        return NGX_CONF_OK!();
    }
    (*conf).logs = (*prev).logs;
    (*conf).off = (*prev).off;
    if !(*conf).logs.is_null() || (*conf).off != 0 {
        return NGX_CONF_OK!();
    }
    (*conf).logs =
        bindings::ngx_array_create((*cf).pool, 2, mem::size_of::<ngx_http_log_t>() as u64);
    if (*conf).logs.is_null() {
        return NGX_CONF_ERROR!();
    }
    log = bindings::ngx_array_push((*conf).logs) as *mut ngx_http_log_t;
    if log.is_null() {
        return NGX_CONF_ERROR!();
    }

    ngx_memzero!(log, mem::size_of::<ngx_http_log_t>());

    (*log).file = bindings::ngx_conf_open_file((*cf).cycle, &mut ngx_http_access_log);
    if (*log).file.is_null() {
        return NGX_CONF_ERROR!();
    }

    lmcf = *ngx_http_conf_get_module_main_conf!(cf, ngx_http_log_module)
        as *mut ngx_http_log_main_conf_t;
    fmt = (*lmcf).formats.elts as *mut ngx_http_log_fmt_t;

    /* the default "combined" format */
    (*log).format = &mut *fmt.offset(0) as *mut ngx_http_log_fmt_t;
    (*lmcf).combined_used = 1;
    return NGX_CONF_OK!();
}

unsafe extern "C" fn ngx_http_log_set_log(
    mut cf: *mut bindings::ngx_conf_t,
    mut cmd: *mut bindings::ngx_command_t,
    mut conf: *mut libc::c_void,
) -> *mut i8 {
    let mut llcf = conf as *mut ngx_http_log_loc_conf_t;
    let mut size: bindings::ssize_t = 0;
    let mut gzip: bindings::ngx_int_t = 0;
    let mut n: bindings::ngx_uint_t = 0;
    let mut flush: bindings::ngx_msec_t = 0;
    let mut value = 0 as *mut bindings::ngx_str_t;
    let mut name = bindings::ngx_str_t {
        len: 0,
        data: ptr::null_mut(),
    };
    let mut s = bindings::ngx_str_t {
        len: 0,
        data: ptr::null_mut(),
    };
    let mut log = 0 as *mut ngx_http_log_t;
    let mut peer = 0 as *mut bindings::ngx_syslog_peer_t;
    let mut buffer = 0 as *mut ngx_http_log_buf_t;
    let mut fmt = 0 as *mut ngx_http_log_fmt_t;
    let mut lmcf = 0 as *mut ngx_http_log_main_conf_t;
    let mut sc = bindings::ngx_http_script_compile_t {
        cf: ptr::null_mut(),
        source: ptr::null_mut(),
        flushes: ptr::null_mut(),
        lengths: ptr::null_mut(),
        values: ptr::null_mut(),
        variables: 0,
        ncaptures: 0,
        captures_mask: 0,
        size: 0,
        main: ptr::null_mut(),
        _bitfield_align_1: [0; 0],
        _bitfield_1: bindings::ngx_http_script_compile_t::new_bitfield_1(0, 0, 0, 0, 0, 0, 0, 0),
        __bindgen_padding_0: [0; 7],
    };
    let mut ccv = bindings::ngx_http_compile_complex_value_t {
        cf: ptr::null_mut(),
        value: ptr::null_mut(),
        complex_value: ptr::null_mut(),
        _bitfield_align_1: [0; 0],
        _bitfield_1: bindings::ngx_http_compile_complex_value_t::new_bitfield_1(0, 0, 0),
        __bindgen_padding_0: [0; 7],
    };
    value = (*(*cf).args).elts as *mut bindings::ngx_str_t;
    if ngx_strcmp!((*value.offset(1)).data, b"off\0" as *const u8) == 0 {
        (*llcf).off = 1;
        if (*(*cf).args).nelts == 2 {
            return NGX_CONF_OK!();
        }
        bindings::ngx_conf_log_error(
            bindings::NGX_LOG_EMERG as usize,
            cf,
            0 as libc::c_int,
            b"invalid parameter \"%V\"\x00" as *const u8 as *const i8,
            &mut *value.offset(2) as *mut bindings::ngx_str_t,
        );
        return NGX_CONF_ERROR!();
    }
    if (*llcf).logs.is_null() {
        (*llcf).logs =
            bindings::ngx_array_create((*cf).pool, 2, mem::size_of::<ngx_http_log_t>() as u64);
        if (*llcf).logs.is_null() {
            return NGX_CONF_ERROR!();
        }
    }
    lmcf = *ngx_http_conf_get_module_main_conf!(cf, ngx_http_log_module)
        as *mut ngx_http_log_main_conf_t;
    log = bindings::ngx_array_push((*llcf).logs) as *mut ngx_http_log_t;
    if log.is_null() {
        return NGX_CONF_ERROR!();
    }

    ngx_memzero!(log, mem::size_of::<ngx_http_log_t>());

    if ngx_strncmp!((*value.offset(1)).data, b"syslog:\0" as *const u8, 7) == 0 {
        peer = bindings::ngx_pcalloc(
            (*cf).pool,
            mem::size_of::<bindings::ngx_syslog_peer_t>() as u64,
        ) as *mut bindings::ngx_syslog_peer_t;
        if peer.is_null() {
            return NGX_CONF_ERROR!();
        }
        if bindings::ngx_syslog_process_conf(cf, peer) != NGX_CONF_OK!() {
            return NGX_CONF_ERROR!();
        }
        (*log).syslog_peer = peer;
    } else {
        n = bindings::ngx_http_script_variables_count(
            &mut *value.offset(1 as libc::c_int as isize),
        );
        if n == 0 {
            (*log).file = bindings::ngx_conf_open_file(
                (*cf).cycle,
                &mut *value.offset(1 as libc::c_int as isize),
            );
            if (*log).file.is_null() {
                return NGX_CONF_ERROR!();
            }
        } else {
            if bindings::ngx_conf_full_name(
                (*cf).cycle,
                &mut *value.offset(1 as libc::c_int as isize),
                0,
            ) != bindings::NGX_OK as isize
            {
                return NGX_CONF_ERROR!();
            }
            (*log).script =
                bindings::ngx_pcalloc((*cf).pool, mem::size_of::<ngx_http_log_script_t>() as u64)
                    as *mut ngx_http_log_script_t;
            if (*log).script.is_null() {
                return NGX_CONF_ERROR!();
            }
            sc.cf = cf;
            sc.source = &mut *value.offset(1) as *mut bindings::ngx_str_t;
            sc.lengths = &mut (*(*log).script).lengths;
            sc.values = &mut (*(*log).script).values;
            sc.variables = n;
            sc.set_complete_lengths(1);
            sc.set_complete_values(1);
            if bindings::ngx_http_script_compile(&mut sc) != bindings::NGX_OK as isize {
                return NGX_CONF_ERROR!();
            }
        }
    }
    if (*(*cf).args).nelts >= 3 {
        name = *value.offset(2);
        if ngx_strcmp!(name.data, b"combined\0" as *const u8) == 0 {
            (*lmcf).combined_used = 1;
        }
    } else {
        ngx_str_set!(&mut name, b"combined\0");
        (*lmcf).combined_used = 1;
    }

    fmt = (*lmcf).formats.elts as *mut ngx_http_log_fmt_t;
    for i in 0..(*lmcf).formats.nelts {
        if (*fmt.offset(i as isize)).name.len == name.len
            && bindings::ngx_strcasecmp((*fmt.offset(i as isize)).name.data, name.data) == 0
        {
            (*log).format = &mut *fmt.offset(i as isize) as *mut ngx_http_log_fmt_t;
            break;
        }
    }
    if (*log).format.is_null() {
        bindings::ngx_conf_log_error(
            bindings::NGX_LOG_EMERG as usize,
            cf,
            0,
            b"unknown log format \"%V\"\x00" as *const u8 as *const i8,
            &mut name as *mut bindings::ngx_str_t,
        );
        return NGX_CONF_ERROR!();
    }

    size = 0;
    flush = 0;
    gzip = 0;

    for i in 3..(*(*cf).args).nelts {
        if ngx_strncmp!(
            (*value.offset(i as isize)).data,
            b"buffer=\0" as *const u8,
            7
        ) == 0
        {
            s.len = (*value.offset(i as isize)).len.wrapping_sub(7);
            s.data = (*value.offset(i as isize)).data.offset(7);
            size = bindings::ngx_parse_size(&mut s);
            if size == bindings::NGX_ERROR as i64 || size == 0 {
                bindings::ngx_conf_log_error(
                    bindings::NGX_LOG_EMERG as usize,
                    cf,
                    0 as libc::c_int,
                    b"invalid buffer size \"%V\"\x00" as *const u8 as *const i8,
                    &mut s as *mut bindings::ngx_str_t,
                );
                return NGX_CONF_ERROR!();
            }
            continue;
        }
        if ngx_strncmp!(
            (*value.offset(i as isize)).data,
            b"flush=\0" as *const u8,
            6
        ) == 0
        {
            s.len = (*value.offset(i as isize)).len.wrapping_sub(6);
            s.data = (*value.offset(i as isize)).data.offset(6);

            flush = bindings::ngx_parse_time(&mut s, 0) as bindings::ngx_msec_t;

            if flush == bindings::NGX_ERROR as bindings::ngx_msec_t || flush == 0 {
                bindings::ngx_conf_log_error(
                    bindings::NGX_LOG_EMERG as usize,
                    cf,
                    0,
                    b"invalid flush time \"%V\"\x00" as *const u8 as *const i8,
                    &mut s as *mut bindings::ngx_str_t,
                );
                return NGX_CONF_ERROR!();
            }
            continue;
        }
        if ngx_strncmp!((*value.offset(i as isize)).data, b"gzip\0" as *const u8, 4) == 0
            && ((*value.offset(i as isize)).len == 4
                || *(*value.offset(i as isize)).data.offset(4) == '=' as u8)
        {
            if cfg!(NGX_ZLIB) {
                if size == 0 {
                    size = 64 * 1024;
                }
                if (*value.offset(i as isize)).len == 4 {
                    gzip = 1; // gzip = bindings::Z_BEST_SPEED;
                    continue;
                }
                s.len = (*value.offset(i as isize)).len - 5;
                s.data = (*value.offset(i as isize)).data.offset(5);

                gzip = bindings::ngx_atoi(s.data, s.len);

                if gzip < 1 || gzip > 9 {
                    bindings::ngx_conf_log_error(
                        bindings::NGX_LOG_EMERG as usize,
                        cf,
                        0,
                        b"invalid compression level \"%V\"\x00" as *const u8 as *const i8,
                        &mut s,
                    );
                    return NGX_CONF_ERROR!();
                }
                continue;
            } else {
                bindings::ngx_conf_log_error(
                    bindings::NGX_LOG_EMERG as usize,
                    cf,
                    0 as libc::c_int,
                    b"nginx was built without zlib support\x00" as *const u8 as *const i8,
                );
                return NGX_CONF_ERROR!();
            }
        }
        if ngx_strncmp!((*value.offset(i as isize)).data, b"if=\0" as *const u8, 3) == 0 {
            s.len = (*value.offset(i as isize)).len.wrapping_sub(3);
            s.data = (*value.offset(i as isize)).data.offset(3 as isize);

            ngx_memzero!(
                &mut ccv,
                mem::size_of::<bindings::ngx_http_compile_complex_value_t>()
            );

            ccv.cf = cf;
            ccv.value = &mut s;
            ccv.complex_value = bindings::ngx_palloc(
                (*cf).pool,
                ::std::mem::size_of::<bindings::ngx_http_complex_value_t>() as libc::c_ulong,
            ) as *mut bindings::ngx_http_complex_value_t;
            if ccv.complex_value.is_null() {
                return NGX_CONF_ERROR!();
            }
            if bindings::ngx_http_compile_complex_value(&mut ccv) != bindings::NGX_OK as isize {
                return NGX_CONF_ERROR!();
            }
            (*log).filter = ccv.complex_value;
            continue;
        }
        bindings::ngx_conf_log_error(
            bindings::NGX_LOG_EMERG as usize,
            cf,
            0,
            b"invalid parameter \"%V\"\x00" as *const u8 as *const i8,
            &mut *value.offset(i as isize) as *mut bindings::ngx_str_t,
        );
        return NGX_CONF_ERROR!();
    }

    if flush != 0 && size == 0 {
        bindings::ngx_conf_log_error(
            bindings::NGX_LOG_EMERG as usize,
            cf,
            0,
            b"no buffer is defined for access_log \"%V\"\x00" as *const u8 as *const i8,
            &mut *value.offset(1) as *mut bindings::ngx_str_t,
        );
        return NGX_CONF_ERROR!();
    }

    if size != 0 {
        if !(*log).script.is_null() {
            bindings::ngx_conf_log_error(
                bindings::NGX_LOG_EMERG as usize,
                cf,
                0,
                b"buffered logs cannot have variables in name\x00" as *const u8 as *const i8,
            );
            return NGX_CONF_ERROR!();
        }
        if !(*log).syslog_peer.is_null() {
            bindings::ngx_conf_log_error(
                bindings::NGX_LOG_EMERG as usize,
                cf,
                0,
                b"logs to syslog cannot be buffered\x00" as *const u8 as *const i8,
            );
            return NGX_CONF_ERROR!();
        }
        if !(*(*log).file).data.is_null() {
            buffer = (*(*log).file).data as *mut ngx_http_log_buf_t;
            if (*buffer).last.offset_from((*buffer).start) != size as isize
                || (*buffer).flush != flush
                || (*buffer).gzip != gzip
            {
                bindings::ngx_conf_log_error(
                    bindings::NGX_LOG_EMERG as usize,
                    cf,
                    0,
                    b"access_log \"%V\" already defined with conflicting parameters\x00"
                        as *const u8 as *const i8,
                    &mut *value.offset(1) as *mut bindings::ngx_str_t,
                );
                return NGX_CONF_ERROR!();
            }
            return NGX_CONF_OK!();
        }
        buffer = bindings::ngx_pcalloc((*cf).pool, mem::size_of::<ngx_http_log_buf_t>() as u64)
            as *mut ngx_http_log_buf_t;
        if buffer.is_null() {
            return NGX_CONF_ERROR!();
        }
        (*buffer).start =
            bindings::ngx_pnalloc((*cf).pool, size as bindings::size_t) as *mut bindings::u_char;
        if (*buffer).start.is_null() {
            return NGX_CONF_ERROR!();
        }

        (*buffer).pos = (*buffer).start;
        (*buffer).last = (*buffer).start.offset(size as isize);
        if flush != 0 {
            (*buffer).event =
                bindings::ngx_pcalloc((*cf).pool, mem::size_of::<bindings::ngx_event_t>() as u64)
                    as *mut bindings::ngx_event_t;
            if (*buffer).event.is_null() {
                return NGX_CONF_ERROR!();
            }

            (*(*buffer).event).data = (*log).file as *mut libc::c_void;
            (*(*buffer).event).handler = Some(ngx_http_log_flush_handler);
            (*(*buffer).event).log = &mut (*(*cf).cycle).new_log;
            (*(*buffer).event).set_cancelable(1);
            (*buffer).flush = flush;
        }
        (*buffer).gzip = gzip;
        (*(*log).file).flush = Some(ngx_http_log_flush);
        (*(*log).file).data = buffer as *mut libc::c_void;
    }
    return NGX_CONF_OK!();
}

unsafe extern "C" fn ngx_http_log_set_format(
    mut cf: *mut bindings::ngx_conf_t,
    mut cmd: *mut bindings::ngx_command_t,
    mut conf: *mut libc::c_void,
) -> *mut i8 {
    let mut lmcf = conf as *mut ngx_http_log_main_conf_t;
    let mut value = 0 as *mut bindings::ngx_str_t;
    let mut fmt = 0 as *mut ngx_http_log_fmt_t;
    value = (*(*cf).args).elts as *mut bindings::ngx_str_t;
    fmt = (*lmcf).formats.elts as *mut ngx_http_log_fmt_t;

    for i in 0..(*lmcf).formats.nelts {
        if (*fmt.offset(i as isize)).name.len == (*value.offset(1)).len
            && ngx_strcmp!(
                (*fmt.offset(i as isize)).name.data,
                (*value.offset(1)).data as *const u8
            ) == 0
        {
            bindings::ngx_conf_log_error(
                bindings::NGX_LOG_EMERG as usize,
                cf,
                0,
                b"duplicate \"log_format\" name \"%V\"\x00" as *const u8 as *const i8,
                &mut *value.offset(1 as libc::c_int as isize) as *mut bindings::ngx_str_t,
            );
            return NGX_CONF_ERROR!();
        }
    }
    fmt = bindings::ngx_array_push(&mut (*lmcf).formats) as *mut ngx_http_log_fmt_t;
    if fmt.is_null() {
        return NGX_CONF_ERROR!();
    }
    (*fmt).name = *value.offset(1);

    (*fmt).flushes = bindings::ngx_array_create(
        (*cf).pool,
        4,
        mem::size_of::<bindings::ngx_int_t>() as libc::c_ulong,
    );
    if (*fmt).flushes.is_null() {
        return NGX_CONF_ERROR!();
    }

    (*fmt).ops = bindings::ngx_array_create(
        (*cf).pool,
        16,
        mem::size_of::<ngx_http_log_op_t>() as libc::c_ulong,
    );
    if (*fmt).ops.is_null() {
        return NGX_CONF_ERROR!();
    }

    return ngx_http_log_compile_format(cf, (*fmt).flushes, (*fmt).ops, (*cf).args, 2);
}

unsafe extern "C" fn ngx_http_log_compile_format(
    mut cf: *mut bindings::ngx_conf_t,
    mut flushes: *mut bindings::ngx_array_t,
    mut ops: *mut bindings::ngx_array_t,
    mut args: *mut bindings::ngx_array_t,
    mut s: bindings::ngx_uint_t,
) -> *mut i8 {
    let mut data = 0 as *mut bindings::u_char;
    let mut p = 0 as *mut bindings::u_char;
    let mut ch: bindings::u_char = 0;
    let mut i: bindings::size_t = 0;
    let mut len: bindings::size_t = 0;
    let mut value = 0 as *mut bindings::ngx_str_t;
    let mut var = bindings::ngx_str_t {
        len: 0,
        data: ptr::null_mut(),
    };
    let mut flush = 0 as *mut bindings::ngx_int_t;
    let mut bracket: bindings::ngx_uint_t = 0;
    let mut escape: bindings::ngx_uint_t = 0;
    let mut op = 0 as *mut ngx_http_log_op_t;
    let mut v = 0 as *mut ngx_http_log_var_t;

    escape = NGX_HTTP_LOG_ESCAPE_DEFAULT as bindings::ngx_uint_t;
    value = (*args).elts as *mut bindings::ngx_str_t;

    if s < (*args).nelts
        && ngx_strncmp!(
            (*value.offset(s as isize)).data,
            b"escape=\0" as *const u8,
            7
        ) == 0
    {
        data = (*value.offset(s as isize)).data.offset(7);

        if ngx_strcmp!(data, b"json\0" as *const u8) == 0 {
            escape = NGX_HTTP_LOG_ESCAPE_JSON as bindings::ngx_uint_t
        } else if ngx_strcmp!(data, b"none\0" as *const u8) == 0 {
            escape = NGX_HTTP_LOG_ESCAPE_NONE as bindings::ngx_uint_t
        } else if ngx_strcmp!(data, b"default\0" as *const u8) != 0 {
            bindings::ngx_conf_log_error(
                bindings::NGX_LOG_EMERG as bindings::ngx_uint_t,
                cf,
                0,
                b"unknown log format escaping \"%s\"\x00" as *const u8 as *const i8,
                data,
            );
            return NGX_CONF_ERROR!();
        }
        s = s.wrapping_add(1);
    }

    let mut invalid: bool = false;

    'outer: loop {
        if !(s < (*args).nelts) {
            invalid = false;
            break;
        }
        i = 0;

        'found: while i < (*value.offset(s as isize)).len {
            op = bindings::ngx_array_push(ops) as *mut ngx_http_log_op_t;
            if op.is_null() {
                return NGX_CONF_ERROR!();
            }

            data =
                &mut *(*value.offset(s as isize)).data.offset(i as isize) as *mut bindings::u_char;

            if *(*value.offset(s as isize)).data.offset(i as isize) as i32 == '$' as i32 {
                i = i.wrapping_add(1);
                if i == (*value.offset(s as isize)).len {
                    invalid = true;
                    break 'outer;
                }
                if *(*value.offset(s as isize)).data.offset(i as isize) as i32 == '{' as i32 {
                    bracket = 1;
                    i = i.wrapping_add(1);
                    if i == (*value.offset(s as isize)).len {
                        invalid = true;
                        break 'outer;
                    }
                    var.data = &mut *(*value.offset(s as isize)).data.offset(i as isize)
                        as *mut bindings::u_char
                } else {
                    bracket = 0;
                    var.data = &mut *(*value.offset(s as isize)).data.offset(i as isize)
                        as *mut bindings::u_char
                }
                var.len = 0;
                while i < (*value.offset(s as isize)).len {
                    ch = *(*value.offset(s as isize)).data.offset(i as isize);
                    if ch as i32 == '}' as i32 && bracket != 0 {
                        i = i.wrapping_add(1);
                        bracket = 0;
                        break;
                    } else {
                        if !(ch as i32 >= 'A' as i32 && ch as i32 <= 'Z' as i32
                            || ch as i32 >= 'a' as i32 && ch as i32 <= 'z' as i32
                            || ch as i32 >= '0' as i32 && ch as i32 <= '9' as i32
                            || ch as i32 == '_' as i32)
                        {
                            break;
                        }
                        i = i.wrapping_add(1);
                        var.len = var.len.wrapping_add(1);
                    }
                }
                if bracket != 0 {
                    bindings::ngx_conf_log_error(
                        bindings::NGX_LOG_EMERG as bindings::ngx_uint_t,
                        cf,
                        0,
                        b"the closing bracket in \"%V\" variable is missing\x00" as *const u8
                            as *const i8,
                        &mut var as *mut bindings::ngx_str_t,
                    );
                    return NGX_CONF_ERROR!();
                }
                if var.len == 0 {
                    invalid = true;
                    break 'outer;
                }
                v = ngx_http_log_vars.as_mut_ptr();
                while (*v).name.len != 0 {
                    if (*v).name.len == var.len
                        && ngx_strncmp!((*v).name.data, var.data as *const u8, var.len)
                            == 0 as libc::c_int
                    {
                        (*op).len = (*v).len;
                        (*op).getlen = None;
                        (*op).run = (*v).run;
                        (*op).data = 0;
                        continue 'found;
                    } else {
                        v = v.offset(1);
                    }
                }
                if ngx_http_log_variable_compile(cf, op, &mut var, escape)
                    != bindings::NGX_OK as isize
                {
                    return NGX_CONF_ERROR!();
                }
                if !flushes.is_null() {
                    flush = bindings::ngx_array_push(flushes) as *mut bindings::ngx_int_t;
                    if flush.is_null() {
                        return NGX_CONF_ERROR!();
                    }
                    *flush = (*op).data as bindings::ngx_int_t;
                    /* variable index */
                }
            } else {
                i = i.wrapping_add(1);
                while i < (*value.offset(s as isize)).len
                    && *(*value.offset(s as isize)).data.offset(i as isize) as i32 != '$' as i32
                {
                    i = i.wrapping_add(1);
                }

                len = (&mut *(*value.offset(s as isize)).data.offset(i as isize)
                    as *mut bindings::u_char)
                    .offset_from(data) as bindings::size_t;

                if len != 0 {
                    (*op).len = len;
                    (*op).getlen = None;
                    if len <= mem::size_of::<libc::uintptr_t>() as libc::c_ulong {
                        (*op).run = Some(ngx_http_log_copy_short);
                        (*op).data = 0;
                        while len != 0 {
                            len = len.wrapping_sub(1);
                            (*op).data <<= 8 as libc::c_int;
                            (*op).data |= *data.offset(len as isize) as usize;
                        }
                    } else {
                        (*op).run = Some(ngx_http_log_copy_long);
                        p = bindings::ngx_pnalloc((*cf).pool, len) as *mut bindings::u_char;
                        if p.is_null() {
                            return NGX_CONF_ERROR!();
                        }
                        ngx_string_macro::ngx_memcpy(p, data, len as usize);
                        (*op).data = p as libc::uintptr_t;
                    }
                }
            }
        }
        s = s.wrapping_add(1)
    }
    match invalid {
        true => {
            bindings::ngx_conf_log_error(
                bindings::NGX_LOG_EMERG as bindings::ngx_uint_t,
                cf,
                0,
                b"invalid parameter \"%s\"\x00" as *const u8 as *const i8,
                data,
            );
            return NGX_CONF_ERROR!();
        }
        false => return NGX_CONF_OK!(),
    };
}

unsafe extern "C" fn ngx_http_log_open_file_cache(
    mut cf: *mut bindings::ngx_conf_t,
    mut cmd: *mut bindings::ngx_command_t,
    mut conf: *mut libc::c_void,
) -> *mut i8 {
    let mut llcf = conf as *mut ngx_http_log_loc_conf_t;
    let mut inactive: bindings::time_t = 0;
    let mut valid: bindings::time_t = 0;
    let mut value = 0 as *mut bindings::ngx_str_t;
    let mut s = bindings::ngx_str_t {
        len: 0,
        data: ptr::null_mut(),
    };
    let mut max: bindings::ngx_int_t = 0;
    let mut min_uses: bindings::ngx_int_t = 0;
    if (*llcf).open_file_cache != NGX_CONF_UNSET_PTR!() as *mut bindings::ngx_open_file_cache_t {
        return b"is duplicate\x00" as *const u8 as *const i8 as *mut i8;
    }
    value = (*(*cf).args).elts as *mut bindings::ngx_str_t;
    max = 0;
    inactive = 10;
    valid = 60;
    min_uses = 1;

    let mut failed: bool = false;
    for i in 1..(*(*cf).args).nelts {
        if ngx_strncmp!((*value.offset(i as isize)).data, b"max=\0" as *const u8, 4) == 0 {
            max = bindings::ngx_atoi(
                (*value.offset(i as isize)).data.offset(4),
                (*value.offset(i as isize)).len.wrapping_sub(4),
            );
            if max == bindings::NGX_ERROR as isize {
                failed = true;
            } else {
                failed = false;
            }
        } else if ngx_strncmp!(
            (*value.offset(i as isize)).data,
            b"inactive=\0" as *const u8,
            9
        ) == 0
        {
            s.len = (*value.offset(i as isize)).len.wrapping_sub(9);
            s.data = (*value.offset(i as isize)).data.offset(9);
            inactive = bindings::ngx_parse_time(&mut s, 1) as i64;
            if inactive == bindings::NGX_ERROR as bindings::time_t {
                failed = true;
            } else {
                failed = false;
            }
        } else if ngx_strncmp!(
            (*value.offset(i as isize)).data,
            b"min_uses=\0" as *const u8,
            9
        ) == 0
        {
            min_uses = bindings::ngx_atoi(
                (*value.offset(i as isize)).data.offset(9),
                (*value.offset(i as isize)).len.wrapping_sub(9),
            );
            if min_uses == bindings::NGX_ERROR as isize {
                failed = true;
            } else {
                failed = false;
            }
        } else if ngx_strncmp!(
            (*value.offset(i as isize)).data,
            b"valid=\0" as *const u8,
            6
        ) == 0
        {
            s.len = (*value.offset(i as isize)).len.wrapping_sub(6);
            s.data = (*value.offset(i as isize)).data.offset(6);
            valid = bindings::ngx_parse_time(&mut s, 1) as i64;
            if valid == bindings::NGX_ERROR as bindings::time_t {
                failed = true;
            } else {
                failed = false;
            }
        } else if ngx_strcmp!((*value.offset(i as isize)).data, b"off\0" as *const u8) == 0 {
            (*llcf).open_file_cache = ptr::null_mut();
            failed = false;
        } else {
            failed = true;
        }
        match failed {
            true => {
                bindings::ngx_conf_log_error(
                    bindings::NGX_LOG_EMERG as bindings::ngx_uint_t,
                    cf,
                    0 as libc::c_int,
                    b"invalid \"open_log_file_cache\" parameter \"%V\"\x00" as *const u8
                        as *const i8,
                    &mut *value.offset(i as isize) as *mut bindings::ngx_str_t,
                );
                return NGX_CONF_ERROR!();
            }
            false => {}
        }
    }
    if (*llcf).open_file_cache.is_null() {
        return NGX_CONF_OK!();
    }
    if max == 0 {
        bindings::ngx_conf_log_error(
            bindings::NGX_LOG_EMERG as bindings::ngx_uint_t,
            cf,
            0,
            b"\"open_log_file_cache\" must have \"max\" parameter\x00" as *const u8 as *const i8,
        );
        return NGX_CONF_ERROR!();
    }

    (*llcf).open_file_cache =
        bindings::ngx_open_file_cache_init((*cf).pool, max as bindings::ngx_uint_t, inactive);

    if !(*llcf).open_file_cache.is_null() {
        (*llcf).open_file_cache_valid = valid;
        (*llcf).open_file_cache_min_uses = min_uses as bindings::ngx_uint_t;
        return NGX_CONF_OK!();
    }
    return NGX_CONF_ERROR!();
}

unsafe extern "C" fn ngx_http_log_init(mut cf: *mut bindings::ngx_conf_t) -> bindings::ngx_int_t {
    let mut value = 0 as *mut bindings::ngx_str_t;
    let mut a = bindings::ngx_array_t {
        elts: 0 as *mut libc::c_void,
        nelts: 0,
        size: 0,
        nalloc: 0,
        pool: 0 as *mut bindings::ngx_pool_t,
    };
    let mut h = 0 as *mut bindings::ngx_http_handler_pt;
    let mut fmt = 0 as *mut ngx_http_log_fmt_t;
    let mut lmcf = 0 as *mut ngx_http_log_main_conf_t;
    let mut cmcf = 0 as *mut bindings::ngx_http_core_main_conf_t;

    lmcf = *ngx_http_conf_get_module_main_conf!(cf, ngx_http_log_module)
        as *mut ngx_http_log_main_conf_t;

    if (*lmcf).combined_used != 0 {
        if ngx_array_macro::ngx_array_init(
            &mut a,
            (*cf).pool,
            1,
            mem::size_of::<bindings::ngx_str_t>() as u64,
        ) != bindings::NGX_OK as isize
        {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }
        value = bindings::ngx_array_push(&mut a) as *mut bindings::ngx_str_t;
        if value.is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }
        *value = ngx_http_combined_fmt;
        fmt = (*lmcf).formats.elts as *mut ngx_http_log_fmt_t;
        if !ngx_http_log_compile_format(cf, ptr::null_mut(), (*fmt).ops, &mut a, 0).is_null() {
            return bindings::NGX_ERROR as bindings::ngx_int_t;
        }
    }
    cmcf = *ngx_http_conf_get_module_main_conf!(cf, bindings::ngx_http_core_module)
        as *mut bindings::ngx_http_core_main_conf_t;
    h = bindings::ngx_array_push(
        &mut ((*cmcf).phases[bindings::ngx_http_phases::NGX_HTTP_LOG_PHASE as usize]).handlers,
    ) as *mut bindings::ngx_http_handler_pt;
    if h.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    *h = Some(ngx_http_log_handler);
    return bindings::NGX_OK as bindings::ngx_int_t;
}
unsafe extern "C" fn run_static_initializers() {
    ngx_http_log_commands = [
        {
            let mut init = bindings::ngx_command_t {
                name: ngx_string!("log_format\0"),
                type_: (bindings::NGX_HTTP_MAIN_CONF | bindings::NGX_CONF_2MORE)
                    as bindings::ngx_uint_t,
                set: Some(ngx_http_log_set_format),
                conf: NGX_HTTP_MAIN_CONF_OFFSET!(),
                offset: 0,
                post: ptr::null_mut(),
            };
            init
        },
        {
            let mut init = bindings::ngx_command_t {
                name: ngx_string!("access_log\0"),
                type_: ((bindings::NGX_HTTP_MAIN_CONF
                    | bindings::NGX_HTTP_SRV_CONF
                    | bindings::NGX_HTTP_LOC_CONF
                    | bindings::NGX_HTTP_LIF_CONF) as libc::c_uint
                    | (bindings::NGX_HTTP_LMT_CONF as libc::c_uint)
                    | bindings::NGX_CONF_1MORE as libc::c_uint)
                    as bindings::ngx_uint_t,
                set: Some(ngx_http_log_set_log),
                conf: NGX_HTTP_LOC_CONF_OFFSET!(),
                offset: 0,
                post: ptr::null_mut(),
            };
            init
        },
        {
            let mut init = bindings::ngx_command_t {
                name: ngx_string!("open_log_file_cache\0"),
                type_: (bindings::NGX_HTTP_MAIN_CONF
                    | bindings::NGX_HTTP_SRV_CONF
                    | bindings::NGX_HTTP_LOC_CONF
                    | bindings::NGX_CONF_TAKE1234) as bindings::ngx_uint_t,
                set: Some(ngx_http_log_open_file_cache),
                conf: NGX_HTTP_LOC_CONF_OFFSET!(),
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
    ngx_http_access_log = ngx_string!(bindings::NGX_HTTP_LOG_PATH);
    ngx_http_combined_fmt = ngx_string!("$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"\0");
    ngx_http_log_vars = [
        {
            let mut init = ngx_http_log_var_t {
                name: ngx_string!("pipe\0"),
                len: 1,
                run: Some(ngx_http_log_pipe),
            };
            init
        },
        {
            let mut init = ngx_http_log_var_t {
                name: ngx_string!("time_local\0"),
                len: (mem::size_of::<[i8; 27]>() as libc::c_ulong).wrapping_sub(1), // sizeof("28/Sep/1970:12:00:00 +0600") - 1
                run: Some(ngx_http_log_time),
            };
            init
        },
        {
            let mut init = ngx_http_log_var_t {
                name: ngx_string!("time_iso8601\0"),
                len: (mem::size_of::<[i8; 26]>() as libc::c_ulong).wrapping_sub(1), // sizeof("1970-09-28T12:00:00+06:00") - 1
                run: Some(ngx_http_log_iso8601),
            };
            init
        },
        {
            let mut init = ngx_http_log_var_t {
                name: ngx_string!("msec\0"),
                len: (mem::size_of::<[i8; 21]>() as libc::c_ulong)
                    .wrapping_sub(1) // (sizeof("-9223372036854775808") - 1)
                    .wrapping_add(4),
                run: Some(ngx_http_log_msec),
            };
            init
        },
        {
            let mut init = ngx_http_log_var_t {
                name: ngx_string!("request_time\0"),
                len: (mem::size_of::<[i8; 21]>() as libc::c_ulong)
                    .wrapping_sub(1) // (sizeof("-9223372036854775808") - 1)
                    .wrapping_add(4),
                run: Some(ngx_http_log_request_time),
            };
            init
        },
        {
            let mut init = ngx_http_log_var_t {
                name: ngx_string!("status\0"),
                len: (::std::mem::size_of::<[i8; 21]>() as libc::c_ulong).wrapping_sub(1), // (sizeof("-9223372036854775808") - 1)
                run: Some(ngx_http_log_status),
            };
            init
        },
        {
            let mut init = ngx_http_log_var_t {
                name: ngx_string!("bytes_sent\0"),
                len: (mem::size_of::<[i8; 21]>() as libc::c_ulong).wrapping_sub(1), // (sizeof("-9223372036854775808") - 1)
                run: Some(ngx_http_log_bytes_sent),
            };
            init
        },
        {
            let mut init = ngx_http_log_var_t {
                name: ngx_string!("body_bytes_sent\0"),
                len: (::std::mem::size_of::<[i8; 21]>() as libc::c_ulong).wrapping_sub(1), // (sizeof("-9223372036854775808") - 1)
                run: Some(ngx_http_log_body_bytes_sent),
            };
            init
        },
        {
            let mut init = ngx_http_log_var_t {
                name: ngx_string!("request_length\0"),
                len: (::std::mem::size_of::<[i8; 21]>() as libc::c_ulong).wrapping_sub(1), // (sizeof("-9223372036854775808") - 1)
                run: Some(ngx_http_log_request_length),
            };
            init
        },
        {
            let mut init = ngx_http_log_var_t {
                name: {
                    let mut init = ngx_null_string!();
                    init
                },
                len: 0,
                run: None,
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
