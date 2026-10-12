// SPDX-License-Identifier: GPL-2.0

//! Global allocator shim for the Linux kernel.
//!
//! The `alloc` crate expects the allocator shim that rustc emits when it links a final artifact.
//! The kernel is linked by ld instead, so provide the shim symbols here, and forward them to
//! functions provided by the code that embeds this crate.

use core::ffi::c_void;

unsafe extern "C" {
    fn efiloader_alloc(size: usize, align: usize, zero: bool) -> *mut c_void;
    fn efiloader_realloc(ptr: *mut c_void, new_size: usize, align: usize) -> *mut c_void;
    fn efiloader_free(ptr: *mut c_void);
}

/// # Safety
///
/// Same as [`GlobalAlloc::alloc()`](core::alloc::GlobalAlloc::alloc).
#[rustc_std_internal_symbol]
unsafe fn __rust_alloc(size: usize, align: usize) -> *mut u8 {
    // SAFETY: efiloader_alloc() has no preconditions: it accepts any size and alignment, and
    // returns either NULL or a suitably sized and aligned allocation.
    unsafe { efiloader_alloc(size, align, false).cast() }
}

/// # Safety
///
/// Same as [`GlobalAlloc::alloc_zeroed()`](core::alloc::GlobalAlloc::alloc_zeroed).
#[rustc_std_internal_symbol]
unsafe fn __rust_alloc_zeroed(size: usize, align: usize) -> *mut u8 {
    // SAFETY: efiloader_alloc() has no preconditions: it accepts any size and alignment, and
    // returns either NULL or a suitably sized and aligned allocation.
    unsafe { efiloader_alloc(size, align, true).cast() }
}

/// # Safety
///
/// Same as [`GlobalAlloc::dealloc()`](core::alloc::GlobalAlloc::dealloc).
#[rustc_std_internal_symbol]
unsafe fn __rust_dealloc(ptr: *mut u8, _size: usize, _align: usize) {
    // SAFETY: The caller guarantees that `ptr` was returned by this allocator, i.e., by
    // efiloader_alloc() or efiloader_realloc(), and that it has not been freed yet.
    unsafe { efiloader_free(ptr.cast()) }
}

/// # Safety
///
/// Same as [`GlobalAlloc::realloc()`](core::alloc::GlobalAlloc::realloc).
#[rustc_std_internal_symbol]
unsafe fn __rust_realloc(ptr: *mut u8, _old_size: usize, align: usize, new_size: usize) -> *mut u8 {
    // SAFETY: The caller guarantees that `ptr` was returned by this allocator, i.e., by
    // efiloader_alloc() or efiloader_realloc(), and that it has not been freed yet.
    unsafe { efiloader_realloc(ptr.cast(), new_size, align).cast() }
}

#[rustc_std_internal_symbol]
fn __rust_alloc_error_handler(size: usize, _align: usize) -> ! {
    panic!("efiloader: failed to allocate {size} bytes");
}

#[rustc_std_internal_symbol]
fn __rust_alloc_error_handler_should_panic_v2() -> u8 {
    1
}

#[rustc_std_internal_symbol]
fn __rust_no_alloc_shim_is_unstable_v2() {}
