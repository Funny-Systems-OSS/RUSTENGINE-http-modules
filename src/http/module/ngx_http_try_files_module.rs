use crate::bindings;
use crate::core::ngx_conf_file_macro;
use crate::core::ngx_module_macro;
use crate::core::ngx_string_macro;
use std::mem;
use std::ptr;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ngx_http_try_file_t {
    pub lengths: *mut bindings::ngx_array_t,
    pub values: *mut bindings::ngx_array_t,
    pub name: bindings::ngx_str_t,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: bindings::__BindgenBitfieldUnit<[u8; 2]>,
    pub __bindgen_padding_0: [u8; 6],
}
impl ngx_http_try_file_t {
    #[inline]
    pub fn code(&self) -> ::std::os::raw::c_uint {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(0usize, 10u8) as u32) }
    }
    #[inline]
    pub fn set_code(&mut self, val: ::std::os::raw::c_uint) {
        unsafe {
            let val: u32 = ::core::mem::transmute(val);
            self._bitfield_1.set(0usize, 10u8, val as u64)
        }
    }
    #[inline]
    pub fn test_dir(&self) -> ::std::os::raw::c_uint {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(10usize, 1u8) as u32) }
    }
    #[inline]
    pub fn set_test_dir(&mut self, val: ::std::os::raw::c_uint) {
        unsafe {
            let val: u32 = ::core::mem::transmute(val);
            self._bitfield_1.set(10usize, 1u8, val as u64)
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ngx_http_try_files_loc_conf_t {
    pub try_files: *mut ngx_http_try_file_t,
}

// Initialized in run_static_initializers
#[no_mangle]
static mut ngx_http_try_files_commands: [bindings::ngx_command_t; 2] = [bindings::ngx_command_t {
    name: bindings::ngx_str_t {
        len: 0,
        data: 0 as *mut u8,
    },
    type_: 0,
    set: None,
    conf: 0,
    offset: 0,
    post: 0 as *mut libc::c_void,
}; 2];

#[no_mangle]
static mut ngx_http_try_files_module_ctx: bindings::ngx_http_module_t = {
    let init = bindings::ngx_http_module_t {
        preconfiguration: None,
        postconfiguration: Some(ngx_http_try_files_init),
        create_main_conf: None,
        init_main_conf: None,
        create_srv_conf: None,
        merge_srv_conf: None,
        create_loc_conf: Some(ngx_http_try_files_create_loc_conf),
        merge_loc_conf: None,
    };
    init
};

#[no_mangle]
pub static mut ngx_http_try_files_module: bindings::ngx_module_t = unsafe {
    {
        let init = bindings::ngx_module_t {
            ctx_index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as usize,
            index: ngx_module_macro::NGX_MODULE_UNSET_INDEX as usize,
            name: ptr::null_mut(),
            spare0: 0 as bindings::ngx_uint_t,
            spare1: 0 as bindings::ngx_uint_t,
            version: bindings::nginx_version as bindings::ngx_uint_t,
            signature: ngx_module_macro::NGX_MODULE_SIGNATURE as *const u8 as *const i8,
            ctx: &ngx_http_try_files_module_ctx as *const bindings::ngx_http_module_t
                as *mut bindings::ngx_http_module_t as *mut libc::c_void,
            commands: ngx_http_try_files_commands.as_ptr() as *mut _,
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

unsafe extern "C" fn ngx_http_try_files_handler(
    mut r: *mut bindings::ngx_http_request_t,
) -> bindings::ngx_int_t {
    let mut name = 0 as *mut bindings::u_char;
    let mut path = bindings::ngx_str_t {
        len: 0,
        data: 0 as *mut bindings::u_char,
    };
    let mut args = bindings::ngx_str_t {
        len: 0,
        data: 0 as *mut bindings::u_char,
    };
    let mut test_dir: bindings::ngx_uint_t = 0;
    let mut tf = 0 as *mut ngx_http_try_file_t;
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
    let mut code: bindings::ngx_http_script_code_pt = None;
    let mut e = bindings::ngx_http_script_engine_t {
        ip: 0 as *mut bindings::u_char,
        pos: 0 as *mut bindings::u_char,
        sp: 0 as *mut bindings::ngx_http_variable_value_t,
        buf: bindings::ngx_str_t {
            len: 0,
            data: 0 as *mut bindings::u_char,
        },
        line: bindings::ngx_str_t {
            len: 0,
            data: 0 as *mut bindings::u_char,
        },
        args: 0 as *mut bindings::u_char,
        _bitfield_align_1: [0; 0],
        _bitfield_1: bindings::ngx_http_script_engine_t::new_bitfield_1(0, 0, 0, 0, 0),
        status: 0,
        request: 0 as *mut bindings::ngx_http_request_t,
    };
    let mut clcf = 0 as *mut bindings::ngx_http_core_loc_conf_t;
    let mut lcode: bindings::ngx_http_script_len_code_pt = None;
    let mut tlcf = 0 as *mut ngx_http_try_files_loc_conf_t;

    tlcf = *ngx_http_get_module_loc_conf!(r, ngx_http_try_files_module)
        as *mut ngx_http_try_files_loc_conf_t;

    if (*tlcf).try_files.is_null() {
        return bindings::NGX_DECLINED as bindings::ngx_int_t;
    }

    ngx_log_debug!(
        bindings::NGX_LOG_DEBUG_HTTP as bindings::ngx_uint_t,
        (*(*r).connection).log,
        0,
        b"try files handler\x00" as *const u8 as *const i8
    );

    let mut allocated: bindings::size_t = 0;
    let mut root: bindings::size_t = 0;
    name = ptr::null_mut();

    /* suppress MSVC warning */
    path.data = ptr::null_mut();

    tf = (*tlcf).try_files;

    clcf = *ngx_http_get_module_loc_conf!(r, bindings::ngx_http_core_module)
        as *mut bindings::ngx_http_core_loc_conf_t;

    let alias: bindings::size_t = (*clcf).alias;

    let mut len: bindings::size_t = 0;
    let mut reserve: bindings::size_t = 0;
    loop {
        if !(*tf).lengths.is_null() {
            ngx_memzero!(&mut e, mem::size_of::<bindings::ngx_http_script_engine_t>());

            e.ip = (*(*tf).lengths).elts as *mut bindings::u_char;
            e.request = r;

            /* 1 is for terminating '\0' as in static names */
            len = 1;

            while *(e.ip as *mut u64) != 0 {
                lcode = *(e.ip as *mut bindings::ngx_http_script_len_code_pt);
                len = (len as libc::c_ulong)
                    .wrapping_add(lcode.expect("non-null function pointer")(&mut e))
                    as bindings::size_t;
            }
        } else {
            len = (*tf).name.len
        }

        if alias == 0 {
            reserve = if len > (*r).uri.len {
                len.wrapping_sub((*r).uri.len)
            } else {
                0
            };
        } else if alias == bindings::NGX_MAX_SIZE_T_VALUE as u64 {
            reserve = len;
        } else {
            reserve = if len > (*r).uri.len.wrapping_sub(alias) {
                len.wrapping_sub((*r).uri.len.wrapping_sub(alias))
            } else {
                0
            };
        }

        if reserve > allocated || allocated == 0 {
            /* 16 bytes are preallocation */
            allocated = reserve.wrapping_add(16);

            if bindings::ngx_http_map_uri_to_path(r, &mut path, &mut root, allocated).is_null() {
                return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
            }

            name = path.data.offset(root as isize)
        }

        if (*tf).values.is_null() {
            /* tf->name.len includes the terminating '\0' */

            ngx_string_macro::ngx_memcpy(name, (*tf).name.data, (*tf).name.len as usize);
            // std::ptr::copy_nonoverlapping((*tf).name.data, name, (*tf).name.len as usize);
            path.len = name
                .offset((*tf).name.len as isize)
                .offset(-1)
                .offset_from(path.data) as bindings::size_t;
        } else {
            e.ip = (*(*tf).values).elts as *mut bindings::u_char;
            e.pos = name;
            e.set_flushed(1);
            while *(e.ip as *mut u64) != 0 {
                code = *(e.ip as *mut bindings::ngx_http_script_code_pt);
                code.expect("non-null function pointer")(
                    &mut e as *mut bindings::ngx_http_script_engine_t,
                );
            }

            path.len = e.pos.offset_from(path.data) as bindings::size_t;

            *e.pos = '\u{0}' as i32 as u8;

            if alias != 0
                && alias != bindings::NGX_MAX_SIZE_T_VALUE as u64
                && ngx_strncmp!(name, (*r).uri.data, alias as usize) == 0
            {
                ptr::copy(
                    name.offset(alias as isize),
                    name,
                    len.wrapping_sub(alias) as usize,
                );
                path.len = path.len.wrapping_sub(alias) as bindings::size_t;
            }
        }
        test_dir = (*tf).test_dir() as bindings::ngx_uint_t;

        tf = tf.offset(1);
        ngx_log_debug!(
            bindings::NGX_LOG_DEBUG_HTTP as bindings::ngx_uint_t,
            (*(*r).connection).log,
            0,
            b"trying to use %s: \"%s\" \"%s\"\x00" as *const u8 as *const i8,
            if test_dir != 0 {
                b"dir\x00" as *const u8 as *const i8
            } else {
                b"file\x00" as *const u8 as *const i8
            },
            name,
            path.data
        );

        if (*tf).lengths.is_null() && (*tf).name.len == 0 {
            if (*tf).code() != 0 {
                return (*tf).code() as bindings::ngx_int_t;
            }

            path.len = path.len.wrapping_sub(root) as bindings::size_t;
            path.data = path.data.offset(root as isize);

            if *path.data.offset(0) as i32 == '@' as i32 {
                bindings::ngx_http_named_location(r, &mut path);
            } else {
                bindings::ngx_http_split_args(r, &mut path, &mut args);
                bindings::ngx_http_internal_redirect(r, &mut path, &mut args);
            }
            bindings::ngx_http_finalize_request(r, bindings::NGX_DONE as bindings::ngx_int_t);
            return bindings::NGX_DONE as bindings::ngx_int_t;
        }

        ngx_memzero!(&mut of, mem::size_of::<bindings::ngx_open_file_info_t>());

        of.read_ahead = (*clcf).read_ahead;
        of.directio = (*clcf).directio;
        of.valid = (*clcf).open_file_cache_valid;
        of.min_uses = (*clcf).open_file_cache_min_uses;
        of.set_test_only(1);
        of.set_errors((*clcf).open_file_cache_errors as u32);
        of.set_events((*clcf).open_file_cache_events as u32);

        if bindings::ngx_http_set_disable_symlinks(r, clcf, &mut path, &mut of)
            != bindings::NGX_OK as bindings::ngx_int_t
        {
            return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
        }
        if bindings::ngx_open_cached_file((*clcf).open_file_cache, &mut path, &mut of, (*r).pool)
            != bindings::NGX_OK as bindings::ngx_int_t
        {
            if of.err == 0 as libc::c_int {
                return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
            }
            if of.err != bindings::NGX_ENOENT as i32
                && of.err != bindings::NGX_ENOTDIR as i32
                && of.err != bindings::NGX_ENAMETOOLONG as i32
            {
                ngx_log_error!(
                    bindings::NGX_LOG_CRIT as usize,
                    (*(*r).connection).log,
                    of.err,
                    b"%s \"%s\" failed\x00" as *const u8 as *const i8,
                    of.failed,
                    path.data
                );
            }
        } else {
            if of.is_dir() != test_dir as u32 {
                continue;
            }

            path.len = (path.len as libc::c_ulong).wrapping_sub(root) as bindings::size_t;
            path.data = path.data.offset(root as isize);

            if alias == 0 {
                (*r).uri = path;
            } else if alias == bindings::NGX_MAX_SIZE_T_VALUE as u64 {
                if test_dir == 0 {
                    (*r).uri = path;
                    (*r).set_add_uri_to_alias(1);
                }
            } else {
                name = (*r).uri.data;
                (*r).uri.len = alias.wrapping_add(path.len);
                (*r).uri.data =
                    bindings::ngx_pnalloc((*r).pool, (*r).uri.len) as *mut bindings::u_char;
                if (*r).uri.data.is_null() {
                    (*r).uri.len = 0;
                    return bindings::NGX_HTTP_INTERNAL_SERVER_ERROR as bindings::ngx_int_t;
                }
                let p: *mut u8 = ngx_string_macro::ngx_cpymem((*r).uri.data, name, alias as usize);
                // std::ptr::copy_nonoverlapping(name, (*r).uri.data, alias as usize);
                // let p: *mut u8 = (*r).uri.data.offset(alias as isize);
                ngx_string_macro::ngx_memcpy(p, path.data, path.len as usize);
                // std::ptr::copy_nonoverlapping(path.data, p, path.len as usize);
            }

            bindings::ngx_http_set_exten(r);

            ngx_log_debug!(
                bindings::NGX_LOG_DEBUG_HTTP as bindings::ngx_uint_t,
                (*(*r).connection).log,
                0,
                b"try file uri: \"%V\"\x00" as *const u8 as *const i8,
                &mut (*r).uri as *mut bindings::ngx_str_t
            );
            return bindings::NGX_DECLINED as bindings::ngx_int_t;
        }
    }
    /* not reached */
}

unsafe extern "C" fn ngx_http_try_files(
    mut cf: *mut bindings::ngx_conf_t,
    mut cmd: *mut bindings::ngx_command_t,
    mut conf: *mut libc::c_void,
) -> *mut libc::c_char {
    let mut tlcf = conf as *mut ngx_http_try_files_loc_conf_t;
    let mut value = 0 as *mut bindings::ngx_str_t;
    let mut code: bindings::ngx_int_t = 0;
    let mut i: bindings::ngx_uint_t = 0;
    let mut n: bindings::ngx_uint_t = 0;
    let mut tf = 0 as *mut ngx_http_try_file_t;
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
    if !(*tlcf).try_files.is_null() {
        return b"is duplicate\x00" as *const u8 as *const i8 as *mut i8;
    }

    tf = bindings::ngx_pcalloc(
        (*cf).pool,
        ((*(*cf).args).nelts as u64).wrapping_mul(mem::size_of::<ngx_http_try_file_t>() as u64),
    ) as *mut ngx_http_try_file_t;

    if tf.is_null() {
        return NGX_CONF_ERROR!();
    }

    (*tlcf).try_files = tf;

    value = (*(*cf).args).elts as *mut bindings::ngx_str_t;

    i = 0;
    while i < (*(*cf).args).nelts.wrapping_sub(1) {
        (*tf.offset(i as isize)).name = *value.offset(i.wrapping_add(1) as isize);

        if (*tf.offset(i as isize)).name.len > 0
            && *(*tf.offset(i as isize))
                .name
                .data
                .offset((*tf.offset(i as isize)).name.len.wrapping_sub(1) as isize)
                as i32
                == '/' as i32
            && i.wrapping_add(2) < (*(*cf).args).nelts
        {
            let ref mut fresh0 = *tf.offset(i as isize);
            (*fresh0).set_test_dir(1);
            let ref mut fresh1 = (*tf.offset(i as isize)).name.len;
            *fresh1 = (*fresh1).wrapping_sub(1);
            *(*tf.offset(i as isize))
                .name
                .data
                .offset((*tf.offset(i as isize)).name.len as isize) = '\0' as u8;
        }

        n = bindings::ngx_http_script_variables_count(&mut (*tf.offset(i as isize)).name);

        if n != 0 {
            ngx_memzero!(
                &mut sc,
                mem::size_of::<bindings::ngx_http_script_compile_t>()
            );

            sc.cf = cf;
            sc.source = &mut (*tf.offset(i as isize)).name;
            sc.lengths = &mut (*tf.offset(i as isize)).lengths;
            sc.values = &mut (*tf.offset(i as isize)).values;
            sc.variables = n;
            sc.set_complete_lengths(1);
            sc.set_complete_values(1);
            if bindings::ngx_http_script_compile(&mut sc) != bindings::NGX_OK as isize {
                return NGX_CONF_ERROR!();
            }
        } else {
            /* add trailing '\0' to length */
            let ref mut fresh2 = (*tf.offset(i as isize)).name.len;
            *fresh2 = (*fresh2).wrapping_add(1)
        }
        i = i.wrapping_add(1);
    }
    if *(*tf.offset(i.wrapping_sub(1) as isize))
        .name
        .data
        .offset(0 as libc::c_int as isize) as libc::c_int
        == '=' as i32
    {
        code = bindings::ngx_atoi(
            (*tf.offset(i.wrapping_sub(1) as isize)).name.data.offset(1),
            (*tf.offset(i.wrapping_sub(1) as isize))
                .name
                .len
                .wrapping_sub(2),
        );
        if code == bindings::NGX_ERROR as isize || code > 999 {
            bindings::ngx_conf_log_error(
                bindings::NGX_LOG_EMERG as bindings::ngx_uint_t,
                cf,
                0,
                b"invalid code \"%*s\"\x00" as *const u8 as *const i8,
                (*tf.offset(i.wrapping_sub(1) as isize))
                    .name
                    .len
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
                (*tf.offset(i.wrapping_sub(1) as isize)).name.data,
            );
            return NGX_CONF_ERROR!();
        }
        let ref mut fresh3 = *tf.offset(i as isize);
        (*fresh3).set_code(code as libc::c_uint)
    }
    return ptr::null_mut();
}

unsafe extern "C" fn ngx_http_try_files_create_loc_conf(
    mut cf: *mut bindings::ngx_conf_t,
) -> *mut libc::c_void {
    let mut tlcf: *mut ngx_http_try_files_loc_conf_t = bindings::ngx_pcalloc(
        (*cf).pool,
        mem::size_of::<ngx_http_try_files_loc_conf_t>() as u64,
    ) as *mut ngx_http_try_files_loc_conf_t;
    if tlcf.is_null() {
        return ptr::null_mut();
    }
    /*
     * set by ngx_pcalloc():
     *
     *     tlcf->try_files = NULL;
     */
    return tlcf as *mut libc::c_void;
}

unsafe extern "C" fn ngx_http_try_files_init(
    mut cf: *mut bindings::ngx_conf_t,
) -> bindings::ngx_int_t {
    let cmcf: *mut bindings::ngx_http_core_main_conf_t =
        *ngx_http_conf_get_module_main_conf!(cf, bindings::ngx_http_core_module)
            as *mut bindings::ngx_http_core_main_conf_t;

    let h: *mut bindings::ngx_http_handler_pt = bindings::ngx_array_push(
        &mut (*(*cmcf)
            .phases
            .as_mut_ptr()
            .offset(bindings::ngx_http_phases::NGX_HTTP_PRECONTENT_PHASE as isize))
        .handlers,
    ) as *mut bindings::ngx_http_handler_pt;
    if h.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    *h = Some(ngx_http_try_files_handler);
    return bindings::NGX_OK as bindings::ngx_int_t;
}
unsafe extern "C" fn run_static_initializers() {
    ngx_http_try_files_commands = [
        {
            let init = bindings::ngx_command_t {
                name: ngx_string!("try_files\0"),
                type_: (bindings::NGX_HTTP_SRV_CONF
                    | bindings::NGX_HTTP_LOC_CONF
                    | bindings::NGX_CONF_2MORE) as bindings::ngx_uint_t,
                set: Some(ngx_http_try_files),
                conf: NGX_HTTP_LOC_CONF_OFFSET!(),
                offset: 0,
                post: ptr::null_mut(),
            };
            init
        },
        {
            let init = ngx_null_command!();
            init
        },
    ]
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
