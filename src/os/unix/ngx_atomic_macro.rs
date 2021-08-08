#[cfg(NGX_PTR_SIZE = "8")]
pub const NGX_ATOMIC_T_LEN: usize = 20; // (sizeof("-9223372036854775808") - 1)

#[cfg(not(NGX_PTR_SIZE = "8"))]
pub const NGX_ATOMIC_T_LEN: usize = 10; // (sizeof("-2147483648") - 1)
