use core::mem;
use libc::size_t;
use ring::digest::{self, Algorithm, Context};

/// # Safety
pub unsafe fn new(algorithm: &'static Algorithm) -> *mut Context {
    let hash = digest::Context::new(algorithm);
    Box::into_raw(Box::new(hash))
}

/// # Safety
pub unsafe fn dispose(hash: *mut Context) {
    drop(Box::from_raw(hash));
}

/// # Safety
pub unsafe fn reset(algorithm: &'static Algorithm, hash: *mut Context) {
    let hash = &mut *hash;
    let new_hash = digest::Context::new(algorithm);
    mem::drop(mem::replace(hash, new_hash));
}

/// # Safety
pub unsafe fn update_final(
    algorithm: &'static Algorithm,
    hash: *mut Context,
    ptr: *const u8,
    size: size_t,
    ptr_out: *mut u8,
    size_out: size_t,
) {
    let hash = &mut *hash;
    let slice = std::slice::from_raw_parts(ptr, size);
    hash.update(slice);

    let slice = std::slice::from_raw_parts_mut(ptr_out, size_out);
    let new_hash = digest::Context::new(algorithm);
    let hash = mem::replace(hash, new_hash);

    slice.copy_from_slice(hash.finish().as_ref());
}

/// # Safety
pub unsafe fn update(hash: *mut Context, ptr: *const u8, size: size_t) {
    let hash = &mut *hash;
    let slice = std::slice::from_raw_parts(ptr, size);
    hash.update(slice);
}

/// # Safety
pub unsafe fn get_hash(
    algorithm: &'static Algorithm,
    hash: *mut Context,
    ptr_out: *mut u8,
    size_out: size_t,
) {
    let hash = &mut *hash;
    let slice = std::slice::from_raw_parts_mut(ptr_out, size_out);

    let new_hash = digest::Context::new(algorithm);
    let hash = mem::replace(hash, new_hash);

    slice.copy_from_slice(hash.finish().as_ref());
}
