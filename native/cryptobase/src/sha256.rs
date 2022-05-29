use libc::size_t;
use sha2::Sha256;

use crate::digest_ffi;

/// # Safety
#[no_mangle]
pub unsafe fn sha256_new() -> *mut Sha256 {
    digest_ffi::new::<Sha256>()
}

/// # Safety
#[no_mangle]
pub unsafe fn sha256_dispose(hash: *mut Sha256) {
    digest_ffi::dispose(hash);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha256_reset(hash: *mut Sha256) {
    digest_ffi::reset(hash);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha256_update_final(
    hash: *mut Sha256,
    ptr: *const u8,
    size: size_t,
    ptr_out: *mut u8,
    size_out: size_t,
) {
    digest_ffi::update_final(hash, ptr, size, ptr_out, size_out);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha256_update(hash: *mut Sha256, ptr: *const u8, size: size_t) {
    digest_ffi::update(hash, ptr, size);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha256_get_hash(hash: *mut Sha256, ptr: *mut u8, size: size_t) {
    digest_ffi::get_hash(hash, ptr, size);
}
