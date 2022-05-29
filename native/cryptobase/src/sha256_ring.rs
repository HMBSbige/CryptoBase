use libc::size_t;
use ring::digest::{self, Context};

use crate::digest_ring_ffi;

/// # Safety
#[no_mangle]
pub unsafe fn sha256_new() -> *mut Context {
    digest_ring_ffi::new(&digest::SHA256)
}

/// # Safety
#[no_mangle]
pub unsafe fn sha256_dispose(hash: *mut Context) {
    digest_ring_ffi::dispose(hash);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha256_reset(hash: *mut Context) {
    digest_ring_ffi::reset(&digest::SHA256, hash);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha256_update_final(
    hash: *mut Context,
    ptr: *const u8,
    size: size_t,
    ptr_out: *mut u8,
    size_out: size_t,
) {
    digest_ring_ffi::update_final(
        &digest::SHA256,
        hash,
        ptr,
        size,
        ptr_out,
        size_out,
    );
}

/// # Safety
#[no_mangle]
pub unsafe fn sha256_update(hash: *mut Context, ptr: *const u8, size: size_t) {
    digest_ring_ffi::update(hash, ptr, size);
}

/// # Safety
#[no_mangle]
pub unsafe fn sha256_get_hash(hash: *mut Context, ptr_out: *mut u8, size_out: size_t) {
    digest_ring_ffi::get_hash(&digest::SHA256, hash, ptr_out, size_out);
}
