macro_rules! ngx_log_debug {
    (
        $($level: expr)*,
        $($log: expr)*,
        $($args: expr), *
    ) => {
        if ((*$($log).*).log_level & $($level).* as usize) != 0 {
            bindings::ngx_log_error_core(
                bindings::NGX_LOG_DEBUG as bindings::ngx_uint_t,
                $($log).*,
                $($args), *);
        }
    };
}

macro_rules! ngx_log_error{
    (
        $($level: expr)*,
        $($log: expr)*,
        $($args: expr), *
    ) => {
        if ((*$($log).*).log_level >= $($level).*) {
            bindings::ngx_log_error_core(
                $($level)*,
                $($log)*,
                $($args), *);
        }
    };
}
