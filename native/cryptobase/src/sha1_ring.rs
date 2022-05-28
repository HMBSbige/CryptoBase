use libc::size_t;
use ring::digest::{self, Context};

use crate::digest_ring_ffi;

/// # Safety
#[no_mangle]
pub unsafe fn sha1_new() -> *mut Context {
    digest_ring_ffi::new(&digest::SHA1_FOR_LEGACY_USE_ONLY)
}

/// # Safety
#[no_mangle]
pub unsafe fn sha1_dispose(hash: *mut Context) {
    digest_ring_ffi::dispose(hash);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha1_reset(hash: *mut Context) {
    digest_ring_ffi::reset(&digest::SHA1_FOR_LEGACY_USE_ONLY, hash);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha1_update_final(
    hash: *mut Context,
    ptr: *const u8,
    size: size_t,
    ptr_out: *mut u8,
    size_out: size_t,
) {
    digest_ring_ffi::update_final(
        &digest::SHA1_FOR_LEGACY_USE_ONLY,
        hash,
        ptr,
        size,
        ptr_out,
        size_out,
    );
}

/// # Safety
#[no_mangle]
pub unsafe fn sha1_update(hash: *mut Context, ptr: *const u8, size: size_t) {
    digest_ring_ffi::update(hash, ptr, size);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha1_get_hash(hash: *mut Context, ptr_out: *mut u8, size_out: size_t) {
    digest_ring_ffi::get_hash(&digest::SHA1_FOR_LEGACY_USE_ONLY, hash, ptr_out, size_out);
}
