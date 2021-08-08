use crate::bindings;

macro_rules! ngx_event_ident{
    ($($p: expr)*) => {
         (*($($p)* as *mut bindings::ngx_connection_t)).fd
    }
}
