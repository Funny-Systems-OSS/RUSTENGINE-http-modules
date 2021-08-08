use crate::bindings;

macro_rules! ngx_time {
    () => {
        (*bindings::ngx_cached_time).sec
    };
}

macro_rules! ngx_timeofday {
    () => {
        bindings::ngx_cached_time as *mut bindings::ngx_time_t
    };
}
