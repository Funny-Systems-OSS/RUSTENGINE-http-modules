pub const LF: u8 = b'\n';
pub const CR: u8 = b'\r';
pub const CRLF: &[u8; 3] = b"\r\n\0";

macro_rules! ngx_abs {
    ($value: expr) => {
        $value.abs()
    };
}

macro_rules! ngx_max {
    ($val1: expr, $val2: expr) => {
        std::cmp::max($val1, $val2)
    };
}

macro_rules! ngx_min {
    ($val1: expr, $val2: expr) => {
        std::cmp::min($val1, $val2)
    };
}
