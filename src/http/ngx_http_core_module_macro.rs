macro_rules! ngx_http_clear_location{
    ($($r_: expr)*) => {
        if !(*$($r_).*).headers_out.location.is_null() {
            (*(*$($r_).*).headers_out.location).hash = 0;
            (*$($r_).*).headers_out.location = std::ptr::null_mut();
        }
    }
}

macro_rules! ngx_http_clear_content_length{
    ($($r_: expr)*) => {
        (*$($r_).*).headers_out.content_length_n = -1;
        if !(*$($r_).*).headers_out.content_length.is_null() {
            (*(*$($r_).*).headers_out.content_length).hash = 0;
            (*$($r_).*).headers_out.content_length = ptr::null_mut()
        }
    }
}

macro_rules! ngx_http_clear_accept_ranges {
    ($($r_: expr)*) => {
        (*$($r_).*).set_allow_ranges(0);
        if !(*$($r_).*).headers_out.accept_ranges.is_null() {
            (*(*$($r_).*).headers_out.accept_ranges).hash = 0;
            (*$($r_).*).headers_out.accept_ranges = ptr::null_mut()
        }
    };
}
