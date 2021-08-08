macro_rules! ngx_http_get_module_ctx {
    (
        $($r_: expr)*,
        $($module: expr)*
    ) => {
        (*$($r_).*).ctx.offset($($module).*.ctx_index as isize);
    };
}

macro_rules! ngx_http_set_ctx {
    (
        $($r_: expr)*,
        $($c: expr)*,
        $($module: expr)*
    ) => {
        *(*$($r_).*).ctx.offset($($module).*.ctx_index as isize) = $($c).*;
    };
}
