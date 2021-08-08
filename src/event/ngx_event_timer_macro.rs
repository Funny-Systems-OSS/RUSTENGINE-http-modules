use crate::bindings;
use std::ptr;

#[inline]
pub unsafe extern "C" fn ngx_event_del_timer(mut ev: *mut bindings::ngx_event_t) {
    ngx_log_debug!(
        bindings::NGX_LOG_DEBUG_EVENT,
        (*ev).log,
        0,
        b"event timer del: %d: %M\x00" as *const u8 as *const libc::c_char,
        ngx_event_ident!((*ev).data),
        (*ev).timer.key
    );
    bindings::ngx_rbtree_delete(&mut bindings::ngx_event_timer_rbtree, &mut (*ev).timer);
    if cfg!(NGX_DEBUG) {
        (*ev).timer.left = ptr::null_mut();
        (*ev).timer.right = ptr::null_mut();
        (*ev).timer.parent = ptr::null_mut();
    }
    (*ev).set_timer_set(0);
}

#[inline]
pub unsafe extern "C" fn ngx_event_add_timer(
    mut ev: *mut bindings::ngx_event_t,
    mut timer: bindings::ngx_msec_t,
) {
    let mut key: bindings::ngx_msec_t = 0;
    let mut diff: bindings::ngx_msec_int_t = 0;
    key = bindings::ngx_current_msec.wrapping_add(timer);
    if (*ev).timer_set() != 0 {
        /*
         * Use a previous timer value if difference between it and a new
         * value is less than NGX_TIMER_LAZY_DELAY milliseconds: this allows
         * to minimize the rbtree operations for fast connections.
         */
        diff = key.wrapping_sub((*ev).timer.key) as bindings::ngx_msec_int_t;
        if ngx_abs!(diff) < bindings::NGX_TIMER_LAZY_DELAY as isize {
            ngx_log_debug!(
                bindings::NGX_LOG_DEBUG_EVENT,
                (*ev).log,
                0,
                b"event timer: %d, old: %M, new: %M\x00" as *const u8 as *const libc::c_char,
                ngx_event_ident!((*ev).data),
                (*ev).timer.key,
                key
            );
            return;
        }
        ngx_event_del_timer(ev);
    }
    (*ev).timer.key = key;

    ngx_log_debug!(
        bindings::NGX_LOG_DEBUG_EVENT,
        (*ev).log,
        0,
        b"event timer add: %d: %M:%M\x00" as *const u8 as *const libc::c_char,
        ngx_event_ident!((*ev).data),
        timer,
        (*ev).timer.key
    );
    bindings::ngx_rbtree_insert(&mut bindings::ngx_event_timer_rbtree, &mut (*ev).timer);
    (*ev).set_timer_set(1);
}
