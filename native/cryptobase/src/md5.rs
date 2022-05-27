use libc::*;
use md5::*;

use crate::digest_ffi;

/// # Safety
#[no_mangle]
pub unsafe fn md5_new() -> *mut Md5 {
    digest_ffi::new::<Md5>()
}

/// # Safety
#[no_mangle]
pub unsafe fn md5_dispose(hash: *mut Md5) {
    digest_ffi::dispose(hash);
}

/// # Safety
#[no_mangle]
pub unsafe fn md5_reset(hash: *mut Md5) {
    digest_ffi::reset(hash);
}

/// # Safety
#[no_mangle]
pub unsafe fn md5_update_final(
    hash: *mut Md5,
    ptr: *const u8,
    size: size_t,
    ptr_out: *mut u8,
    size_out: size_t,
) {
    digest_ffi::update_final(hash, ptr, size, ptr_out, size_out);
}

/// # Safety
#[no_mangle]
pub unsafe fn md5_update(hash: *mut Md5, ptr: *const u8, size: size_t) {
    digest_ffi::update(hash, ptr, size);
}

/// # Safety
#[no_mangle]
pub unsafe fn md5_get_hash(hash: *mut Md5, ptr: *mut u8, size: size_t) {
    digest_ffi::get_hash(hash, ptr, size);
}
