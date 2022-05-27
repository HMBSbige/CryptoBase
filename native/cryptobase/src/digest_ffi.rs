use digest::*;
use libc::*;

/// # Safety
pub unsafe fn new<T: Digest>() -> *mut T {
    Box::into_raw(Box::new(T::new()))
}

/// # Safety
pub unsafe fn dispose<T>(raw: *mut T) {
    Box::from_raw(raw);
}

/// # Safety
pub unsafe fn reset<T: Reset>(hash: *mut T) {
    let hash = &mut *hash;
    hash.reset();
}

/// # Safety
pub unsafe fn update_final<T: Digest + FixedOutputReset>(
    hash: *mut T,
    ptr: *const u8,
    size: size_t,
    ptr_out: *mut u8,
    size_out: size_t,
) {
    let hash = &mut *hash;
    let slice = std::slice::from_raw_parts(ptr, size);
    digest::Update::update(hash, slice);
    let slice = std::slice::from_raw_parts_mut(ptr_out, size_out);
    slice.copy_from_slice(hash.finalize_reset().as_slice());
}

/// # Safety
pub unsafe fn update<T: Digest>(hash: *mut T, ptr: *const u8, size: size_t) {
    let hash = &mut *hash;
    let slice = std::slice::from_raw_parts(ptr, size);
    hash.update(slice);
}

/// # Safety
pub unsafe fn get_hash<T: Digest + FixedOutputReset>(hash: *mut T, ptr: *mut u8, size: size_t) {
    let hash = &mut *hash;
    let slice = std::slice::from_raw_parts_mut(ptr, size);
    slice.copy_from_slice(hash.finalize_reset().as_slice());
}
