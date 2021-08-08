macro_rules! ngx_http_set_log_request {
    (
        $($log: expr)*,
        $($r_: expr)*
    ) => {
        (*((*$($log).*).data as *mut bindings::ngx_http_log_ctx_t)).current_request = $($r_).*;
    };
}
