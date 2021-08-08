macro_rules! ngx_errno {
    () => {
        *(libc::__errno_location())
    };
}
