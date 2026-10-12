// SPDX-License-Identifier: GPL-2.0

//! A minimal first-fit heap allocator, implementing the subset of the `linked_list_allocator`
//! crate's `Heap` API that is used by the EFI pool allocator.
//!
//! Free memory is kept on an address ordered singly linked list of holes, whose headers live in
//! the free memory itself. All sizes are rounded up to, and all blocks are aligned to, at least
//! `MIN_SIZE` bytes, which guarantees that every fragment can hold a hole header.

use core::alloc::Layout;
use core::mem::{align_of, size_of, MaybeUninit};
use core::ptr::{self, NonNull};

struct Hole {
    size: usize,
    next: Option<NonNull<Hole>>,
}

const MIN_SIZE: usize = 2 * size_of::<usize>();
const _: () = assert!(size_of::<Hole>() <= MIN_SIZE && align_of::<Hole>() <= MIN_SIZE);

pub(crate) struct Heap {
    bottom: *mut u8,
    size: usize,
    head: Option<NonNull<Hole>>,
}

// SAFETY: the heap only hands out memory it owns
unsafe impl Send for Heap {}

fn round_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

impl Heap {
    /// Create a heap covering `mem`, which must be `MIN_SIZE` aligned.
    pub(crate) fn from_slice(mem: &'static mut [MaybeUninit<u8>]) -> Heap {
        let mut h = Heap {
            bottom: mem.as_mut_ptr() as *mut u8,
            size: 0,
            head: None,
        };
        // SAFETY: we own `mem`
        unsafe { h.extend(mem.len() & !(MIN_SIZE - 1)) };
        h
    }

    pub(crate) fn bottom(&self) -> *mut u8 {
        self.bottom
    }

    fn layout_size_align(layout: &Layout) -> (usize, usize) {
        let align = layout.align().max(MIN_SIZE);
        (round_up(layout.size().max(1), MIN_SIZE), align)
    }

    /// Add the `by` bytes of memory that immediately follow the heap to the heap.
    ///
    /// # Safety
    ///
    /// The memory in question must be owned by the caller and unused.
    pub(crate) unsafe fn extend(&mut self, by: usize) {
        let by = by & !(MIN_SIZE - 1);
        if by == 0 {
            return;
        }
        // SAFETY: the caller guarantees ownership
        let top = unsafe { self.bottom.add(self.size) };
        self.size += by;
        // SAFETY: the region is unused, aligned and large enough to carry a hole header
        unsafe { self.free_region(top, by) };
    }

    pub(crate) fn allocate_first_fit(&mut self, layout: Layout) -> Result<NonNull<u8>, ()> {
        let (size, align) = Self::layout_size_align(&layout);

        let mut prev: Option<NonNull<Hole>> = None;
        let mut cur = self.head;
        while let Some(mut h) = cur {
            // SAFETY: all holes on the list are valid
            let hole = unsafe { h.as_mut() };
            let start = h.as_ptr() as usize;
            let end = start + hole.size;

            let mut a = round_up(start, align);
            if a != start && a - start < MIN_SIZE {
                a += align;
            }

            if a + size <= end {
                let next = hole.next;

                // Unlink the hole
                match prev {
                    // SAFETY: valid hole
                    Some(mut p) => unsafe { p.as_mut().next = next },
                    None => self.head = next,
                }

                // Return the leading and trailing fragments to the free list
                // SAFETY: both fragments are unused memory owned by the heap
                unsafe {
                    if a > start {
                        self.free_region(start as *mut u8, a - start);
                    }
                    if end > a + size {
                        self.free_region((a + size) as *mut u8, end - (a + size));
                    }
                }
                return NonNull::new(a as *mut u8).ok_or(());
            }
            prev = cur;
            cur = hole.next;
        }
        Err(())
    }

    /// Return the allocation at `ptr` to the heap.
    ///
    /// # Safety
    ///
    /// `ptr` and `layout` must describe a live allocation returned by `allocate_first_fit()`.
    pub(crate) unsafe fn deallocate(&mut self, ptr: NonNull<u8>, layout: Layout) {
        let (size, _) = Self::layout_size_align(&layout);
        // SAFETY: guaranteed by the caller
        unsafe { self.free_region(ptr.as_ptr(), size) };
    }

    /// Insert `[addr, addr + size)` into the address ordered free list, merging it with its
    /// neighbours where possible.
    ///
    /// # Safety
    ///
    /// `[addr, addr + size)` must be unused memory that is owned by the heap, and that is not on
    /// the free list already. `addr` must be `MIN_SIZE` aligned, and `size` must be a non-zero
    /// multiple of `MIN_SIZE`.
    unsafe fn free_region(&mut self, addr: *mut u8, size: usize) {
        let start = addr as usize;
        let end = start + size;

        let mut prev: Option<NonNull<Hole>> = None;
        let mut cur = self.head;
        while let Some(h) = cur {
            if h.as_ptr() as usize > start {
                break;
            }
            prev = cur;
            // SAFETY: valid hole
            cur = unsafe { h.as_ref().next };
        }

        // Merge with the following hole if adjacent
        let (size, next) = match cur {
            // SAFETY: valid hole
            Some(n) if n.as_ptr() as usize == end => unsafe {
                (size + n.as_ref().size, n.as_ref().next)
            },
            _ => (size, cur),
        };

        // Merge with the preceding hole if adjacent
        if let Some(mut p) = prev {
            // SAFETY: valid hole
            let ph = unsafe { p.as_mut() };
            if p.as_ptr() as usize + ph.size == start {
                ph.size += size;
                ph.next = next;
                return;
            }
        }

        let new = addr as *mut Hole;
        // SAFETY: `addr` is MIN_SIZE aligned unused memory of at least MIN_SIZE bytes
        unsafe { ptr::write(new, Hole { size, next }) };
        let new = NonNull::new(new);
        match prev {
            // SAFETY: valid hole
            Some(mut p) => unsafe { p.as_mut().next = new },
            None => self.head = new,
        }
    }
}
