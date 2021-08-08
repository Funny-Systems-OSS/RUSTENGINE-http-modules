use crate::bindings;

macro_rules! NGX_HTTP_MAIN_CONF_OFFSET {
    () => {
        offset_of!(bindings::ngx_http_conf_ctx_t, main_conf);
    };
}

macro_rules! NGX_HTTP_SRV_CONF_OFFSET {
    () => {
        offset_of!(bindings::ngx_http_conf_ctx_t, srv_conf);
    };
}

macro_rules! NGX_HTTP_LOC_CONF_OFFSET {
    () => {
        offset_of!(bindings::ngx_http_conf_ctx_t, loc_conf);
    };
}

macro_rules! ngx_http_get_module_main_conf {
    (
        $($r_: expr)*,
        $($module: expr)*
    ) => {
        (*($($r_)*)).main_conf.wrapping_offset($($module)*.ctx_index as isize);
    };
}

macro_rules! ngx_http_get_module_srv_conf {
    (
        $($r_: expr)*,
        $($module: expr)*
    ) => {
        (*($($r_)*)).srv_conf.wrapping_offset($($module)*.ctx_index as isize);
    };
}

macro_rules! ngx_http_get_module_loc_conf {
    (
        $($r_: expr)*,
        $($module: expr)*
    ) => {
        (*($($r_)*)).loc_conf.wrapping_offset($($module)*.ctx_index as isize);
    };
}

macro_rules! ngx_http_conf_get_module_main_conf {
    ($($cf: expr)*,
    $($module: expr)*) => {
        (*((*($($cf).*)).ctx as *mut bindings::ngx_http_conf_ctx_t)).main_conf.wrapping_offset($($module)*.ctx_index as isize);
    };
}

macro_rules! ngx_http_conf_get_module_srv_conf {
    ($($cf: expr)*,
    $($module: expr)*) => {
        (*((*($($cf).*)).ctx as *mut bindings::ngx_http_conf_ctx_t)).srv_conf.wrapping_offset($($module)*.ctx_index as isize);
    };
}

macro_rules! ngx_http_conf_get_module_loc_conf {
    ($($cf: expr)*,
    $($module: expr)*) => {
        (*((*($($cf).*)).ctx as *mut bindings::ngx_http_conf_ctx_t)).loc_conf.wrapping_offset($($module)*.ctx_index as isize);
    };
}

macro_rules! ngx_http_cycle_get_module_main_conf {
    ($($cycle: expr)*,
    $($module: expr)*) => {
        if !(*$($cycle)*).conf_ctx.wrapping_offset($($module)*.ctx_index as isize).is_null() {
            (*( as *mut bindings::ngx_http_conf_ctx_t)).main_conf.wrapping_offset($($module)*.ctx_index as isize)
        }else{
            ptr::null_mut()
        }
    };
}
