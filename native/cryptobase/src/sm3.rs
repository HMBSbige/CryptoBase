use libc::size_t;
use sm3::Sm3;

use crate::digest_ffi;

/// # Safety
#[no_mangle]
pub unsafe fn sm3_new() -> *mut Sm3 {
    digest_ffi::new::<Sm3>()
}

/// # Safety
#[no_mangle]
pub unsafe fn sm3_dispose(hash: *mut Sm3) {
    digest_ffi::dispose(hash);
}

/// # Safety
#[no_mangle]
pub unsafe fn sm3_reset(hash: *mut Sm3) {
    digest_ffi::reset(hash);
}

/// # Safety
#[no_mangle]
pub unsafe fn sm3_update_final(
    hash: *mut Sm3,
    ptr: *const u8,
    size: size_t,
    ptr_out: *mut u8,
    size_out: size_t,
) {
    digest_ffi::update_final(hash, ptr, size, ptr_out, size_out);
}

/// # Safety
#[no_mangle]
pub unsafe fn sm3_update(hash: *mut Sm3, ptr: *const u8, size: size_t) {
    digest_ffi::update(hash, ptr, size);
}

/// # Safety
#[no_mangle]
pub unsafe fn sm3_get_hash(hash: *mut Sm3, ptr: *mut u8, size: size_t) {
    digest_ffi::get_hash(hash, ptr, size);
}
