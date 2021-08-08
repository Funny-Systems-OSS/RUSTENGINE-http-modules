#[cfg(NGX_HAVE_FILE_AIO)]
#[link(name = "ngx_file_aio_read")]
extern "C" {
    pub fn ngx_file_aio_read(
        file: *mut bindings::ngx_file_t,
        buf: *mut bindings::u_char,
        size: *mut bindings::size_t
        offset: *mut bindings::off_t
        pool: *mut bindings::ngx_pool_t
    ) -> bindings::ssize_t;
}