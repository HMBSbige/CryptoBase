use libc::size_t;
use sha2::Sha512;

use crate::digest_ffi;

/// # Safety
#[no_mangle]
pub unsafe fn sha512_new() -> *mut Sha512 {
    digest_ffi::new::<Sha512>()
}

/// # Safety
#[no_mangle]
pub unsafe fn sha512_dispose(hash: *mut Sha512) {
    digest_ffi::dispose(hash);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha512_reset(hash: *mut Sha512) {
    digest_ffi::reset(hash);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha512_update_final(
    hash: *mut Sha512,
    ptr: *const u8,
    size: size_t,
    ptr_out: *mut u8,
    size_out: size_t,
) {
    digest_ffi::update_final(hash, ptr, size, ptr_out, size_out);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha512_update(hash: *mut Sha512, ptr: *const u8, size: size_t) {
    digest_ffi::update(hash, ptr, size);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha512_get_hash(hash: *mut Sha512, ptr: *mut u8, size: size_t) {
    digest_ffi::get_hash(hash, ptr, size);
}
