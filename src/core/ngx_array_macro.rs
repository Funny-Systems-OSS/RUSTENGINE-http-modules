use crate::bindings;

pub unsafe extern "C" fn ngx_array_init(
    mut array: *mut bindings::ngx_array_t,
    mut pool: *mut bindings::ngx_pool_t,
    mut n: bindings::ngx_uint_t,
    mut size: bindings::size_t,
) -> bindings::ngx_int_t {
    /*
     * set "array->nelts" before "array->elts", otherwise MSVC thinks
     * that "array->nelts" may be used without having been initialized
     */
    (*array).nelts = 0 as bindings::ngx_uint_t;
    (*array).size = size;
    (*array).nalloc = n;
    (*array).pool = pool;
    (*array).elts = bindings::ngx_palloc(pool, (n as u64).wrapping_mul(size));
    if (*array).elts.is_null() {
        return bindings::NGX_ERROR as bindings::ngx_int_t;
    }
    return bindings::NGX_OK as bindings::ngx_int_t;
}
