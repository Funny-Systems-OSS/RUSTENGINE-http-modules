macro_rules! ngx_buf_size {
    ($($b: expr)*) => {
        match ngx_buf_in_memory!($($b).*) {
            true => (*$($b).*).last.offset_from((*$($b).*).pos) as i64,
            false => (((*$($b).*).file_last as i64) - (*$($b).*).file_pos as i64)
        }
    };
}

macro_rules! ngx_buf_in_memory {
    ($($b: expr)*) => {
        (*$($b).*).temporary() != 0 || (*$($b).*).memory() != 0 || (*$($b).*).mmap() != 0
    };
}

macro_rules! ngx_calloc_buf {
    ($($pool: expr)*) => {
        bindings::ngx_pcalloc($($pool).*, (std::mem::size_of::<bindings::ngx_buf_t>()) as bindings::size_t);
    };
}

macro_rules! ngx_buf_special {
    ($($b: expr)*) => {
        (((*$($b).*).flush() == 1 || (*$($b).*).last_buf() ==1 || (*$($b).*).sync() == 1)
        && !ngx_buf_in_memory!($($b).*) && (*$($b).*).in_file() != 1)
    };
}

macro_rules! ngx_free_chain {
    ($($pool: expr)*,
    $($cl: expr)*) => {
        (*($($cl)*)).next = (*($($pool)*)).chain;
        (*($($pool)*)).chain = ($($cl)*);
    };
}
