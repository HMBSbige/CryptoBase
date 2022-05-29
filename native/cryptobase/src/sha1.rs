use libc::size_t;
use sha1::Sha1;

use crate::digest_ffi;

/// # Safety
#[no_mangle]
pub unsafe fn sha1_new() -> *mut Sha1 {
    digest_ffi::new::<Sha1>()
}

/// # Safety
#[no_mangle]
pub unsafe fn sha1_dispose(hash: *mut Sha1) {
    digest_ffi::dispose(hash);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha1_reset(hash: *mut Sha1) {
    digest_ffi::reset(hash);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha1_update_final(
    hash: *mut Sha1,
    ptr: *const u8,
    size: size_t,
    ptr_out: *mut u8,
    size_out: size_t,
) {
    digest_ffi::update_final(hash, ptr, size, ptr_out, size_out);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha1_update(hash: *mut Sha1, ptr: *const u8, size: size_t) {
    digest_ffi::update(hash, ptr, size);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha1_get_hash(hash: *mut Sha1, ptr: *mut u8, size: size_t) {
    digest_ffi::get_hash(hash, ptr, size);
}
