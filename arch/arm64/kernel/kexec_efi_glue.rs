// SPDX-License-Identifier: GPL-2.0

//! Glue between the arm64 kexec loader for EFI images and the efiloader crate.
//!
//! The C side of the loader (`kexec_efi.c`) describes the memory map, the configuration tables
//! and the image, initrd and command line to load, and invokes [`efi_kexec_run`] via
//! `efi_kexec_call()` from a kernel thread, with preemption disabled and an identity map of all
//! EFI managed memory installed in TTBR0. This code then instantiates the EFI runtime, loads the
//! image and starts it. When the image calls `ExitBootServices()`, control is returned to the C
//! side directly by the assembler routine that implements it, and the EFI runtime is torn down by
//! [`efi_kexec_teardown`].

use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::fmt;
use core::mem::MaybeUninit;
use core::ops::Range;
use core::ptr;

use kernel::bindings;

use efiloader::memmap::MemoryMap;
use efiloader::memorytype::EfiMemoryType;
use efiloader::{FileLoader, Guid};

const __LOG_PREFIX: &[u8] = b"kexec_efi\0";

// ---------------------------------------------------------------------------------------------
// Interface with the C side - keep in sync with struct efi_kexec_params in kexec_efi.c
// ---------------------------------------------------------------------------------------------

/// The region may be allocated from by the EFI runtime.
const REGION_ALLOCATABLE: u32 = 1 << 0;

#[repr(C)]
struct Region {
    base: u64,
    size: u64,
    attr: u64,
    r#type: u32,
    flags: u32,
}

#[repr(C)]
struct CfgTable {
    guid: Guid,
    table: u64,
}

#[repr(C)]
struct Params {
    image: *const u8,
    image_size: usize,
    initrd: *const u8,
    initrd_size: usize,
    cmdline: *const u8,
    cmdline_size: usize,

    regions: *const Region,
    nr_regions: usize,
    tables: *const CfgTable,
    nr_tables: usize,

    /// Runtime services table of the real firmware, to be exposed to the OS, or 0
    fw_runtime: u64,
    /// Initial stack pointer value for the image
    stack_top: u64,
    /// Set on return: the EFI system table passed to the image
    systab: u64,
}

// The parameters are only accessed by the kernel thread running the EFI image
struct ParamsHolder(UnsafeCell<*mut Params>);
// SAFETY: see above
unsafe impl Sync for ParamsHolder {}
static PARAMS: ParamsHolder = ParamsHolder(UnsafeCell::new(ptr::null_mut()));

// The loaded image, which needs to be released explicitly at teardown time, given that the
// stack frame of efi_kexec_run() is abandoned when the image calls ExitBootServices().
struct ImageHolder(UnsafeCell<Option<efiloader::LoadedImageData>>);
// SAFETY: only accessed by the kernel thread running the EFI image
unsafe impl Sync for ImageHolder {}
static IMAGE: ImageHolder = ImageHolder(UnsafeCell::new(None));

fn params() -> &'static mut Params {
    // SAFETY: only called while efi_kexec_run() is active
    unsafe { &mut **PARAMS.0.get() }
}

// ---------------------------------------------------------------------------------------------
// efiloader platform hooks
// ---------------------------------------------------------------------------------------------

fn log(level: efiloader::log::Level, args: fmt::Arguments<'_>) {
    use efiloader::log::Level::*;
    match level {
        Error => kernel::pr_err!("{}\n", args),
        Warn => kernel::pr_warn!("{}\n", args),
        Info => kernel::pr_info!("{}\n", args),
        Debug | Trace => kernel::pr_debug!("{}\n", args),
    }
}

/// Console output of the EFI image is collected into lines and emitted via printk().
struct Console {
    line: UnsafeCell<([u8; 160], usize)>,
}
// SAFETY: only used by the kernel thread running the EFI image
unsafe impl Sync for Console {}

impl Console {
    fn flush(&self, buf: &mut ([u8; 160], usize)) {
        if buf.1 > 0 {
            kernel::pr_info!("{}\n", core::str::from_utf8(&buf.0[..buf.1]).unwrap_or("?"));
            buf.1 = 0;
        }
    }
}

impl efiloader::SimpleConsole for Console {
    fn write_string(&self, s: &str) {
        // SAFETY: single threaded, no re-entrancy
        let buf = unsafe { &mut *self.line.get() };
        for c in s.chars() {
            match c {
                '\r' => {}
                '\n' => self.flush(buf),
                c => {
                    let mut tmp = [0u8; 4];
                    let e = c.encode_utf8(&mut tmp).as_bytes();
                    if buf.1 + e.len() > buf.0.len() {
                        self.flush(buf);
                    }
                    buf.0[buf.1..buf.1 + e.len()].copy_from_slice(e);
                    buf.1 += e.len();
                }
            }
        }
    }

    fn read_byte(&self) -> Option<u8> {
        None
    }
}

static CONSOLE: Console = Console {
    line: UnsafeCell::new(([0; 160], 0)),
};

/// All EFI managed memory is mapped read-write-execute in the identity map, so there is
/// nothing to do here.
struct Mapper;

impl efiloader::MemoryMapper for Mapper {
    fn remap_range(&self, _range: &Range<usize>, _set: u64, _clr: u64) -> Result<(), &str> {
        Ok(())
    }

    fn query_range(&self, _range: &Range<usize>) -> Option<u64> {
        Some(0)
    }
}

struct Random;

impl efiloader::Random for Random {
    fn get_entropy(&self, bytes: &mut [u8], _use_raw: bool) -> bool {
        // SAFETY: `bytes` is a valid buffer
        unsafe { bindings::get_random_bytes(bytes.as_mut_ptr().cast(), bytes.len()) };
        true
    }
}

/// A file (the kernel image or initrd) that the C side has loaded into kernel memory.
struct MemFile {
    data: *const u8,
    size: usize,
}

// SAFETY: the memory is owned by the kexec image, which outlives the EFI runtime
unsafe impl Send for MemFile {}

impl FileLoader for MemFile {
    fn get_size(&self) -> usize {
        self.size
    }

    fn load_file<'a>(&self, loadbuffer: &'a mut [MaybeUninit<u8>]) -> Result<&'a [u8], &str> {
        if loadbuffer.len() < self.size {
            return Err("Buffer too small");
        }
        // SAFETY: both buffers are valid for the given sizes
        unsafe {
            self.load_range(loadbuffer.as_mut_ptr().cast(), 0, loadbuffer.len())?;
            Ok(core::slice::from_raw_parts(
                loadbuffer.as_ptr().cast(),
                loadbuffer.len(),
            ))
        }
    }

    unsafe fn load_range<'a>(&self, buf: *mut (), offset: usize, size: usize) -> Result<(), &str> {
        if offset > self.size {
            return Err("Offset out of range");
        }
        let len = size.min(self.size - offset);
        let dst = buf.cast::<u8>();
        // SAFETY: the caller guarantees that `buf` covers `size` bytes
        unsafe {
            ptr::copy_nonoverlapping(self.data.add(offset), dst, len);
            ptr::write_bytes(dst.add(len), 0, size - len);
        }
        Ok(())
    }
}

extern "efiapi" {
    fn efi_kexec_exit_boot_services(handle: usize, map_key: usize) -> efiloader::status::Status;
}

/// Called by efi_kexec_exit_boot_services() to validate the map key. Returns the location
/// where the image's register state should be captured, or NULL if the call should fail.
#[no_mangle]
extern "C" fn efi_kexec_ebs_check(_handle: usize, map_key: usize) -> *mut c_void {
    let efi = efiloader::context();
    if map_key != efi.memmap_key() {
        kernel::pr_warn!("ExitBootServices() called with stale map key\n");
        return ptr::null_mut();
    }

    // Hand the real firmware's runtime services to the incoming kernel
    let fw_runtime = params().fw_runtime;
    efi.set_runtime_services_table(fw_runtime as *const ());

    // SAFETY: provided by the C side
    unsafe { efi_kexec_resume_block() }
}

extern "C" {
    fn efi_kexec_resume_block() -> *mut c_void;
}

/// Instantiate the EFI runtime and run the image until it calls ExitBootServices().
///
/// Returns a negative errno value on failure. Does not return at all on success: the
/// ExitBootServices() implementation unwinds straight into efi_kexec_call().
///
/// # Safety
///
/// Must be called via efi_kexec_call() with a valid `struct efi_kexec_params`, and with all
/// regions described in it identity mapped.
#[no_mangle]
unsafe extern "C" fn efi_kexec_run(p: *mut c_void) -> isize {
    // SAFETY: guaranteed by the caller
    unsafe { *PARAMS.0.get() = p.cast() };
    let p = params();

    efiloader::log::set_logger(log);

    let memmap = MemoryMap::new();
    // SAFETY: guaranteed by the caller
    let regions = unsafe { core::slice::from_raw_parts(p.regions, p.nr_regions) };
    for r in regions {
        let Some(end) = r.base.checked_add(r.size) else {
            kernel::pr_err!("Invalid region {:#x} size {:#x}\n", r.base, r.size);
            return -(bindings::EINVAL as isize);
        };
        let range = r.base as usize..end as usize;
        // SAFETY: EfiMemoryType is repr(u32), and the C side only passes valid types
        let t: EfiMemoryType = unsafe { core::mem::transmute(r.r#type) };
        let ret = if r.flags & REGION_ALLOCATABLE != 0 {
            // SAFETY: allocatable regions are part of the memory that kexec_efi.c set aside for
            // the EFI runtime, which is identity mapped, and not used for anything else until
            // efi_kexec_teardown() has torn down the EFI runtime.
            unsafe { memmap.declare_memory_region(&range) }
        } else if r.attr & efiloader::memorytype::EFI_MEMORY_RUNTIME != 0 {
            // Describe the firmware's runtime regions in the Memory Attributes Table that is
            // exposed to the OS, using permissions that follow from the region type.
            let rtattr = match t {
                EfiMemoryType::EfiRuntimeServicesCode => efiloader::memorytype::EFI_MEMORY_RO,
                _ => efiloader::memorytype::EFI_MEMORY_XP,
            };
            memmap.declare_runtime_region(&range, t, r.attr, rtattr)
        } else {
            memmap.declare_typed_region(&range, t, r.attr)
        };
        if ret.is_err() {
            kernel::pr_err!(
                "Failed to declare region {:#x}-{:#x}\n",
                range.start,
                range.end
            );
            return -(bindings::EINVAL as isize);
        }
    }

    let con: &'static dyn efiloader::SimpleConsole = &CONSOLE;
    let Ok(efi) = efiloader::init(Some(con), memmap, Mapper, Some(Random)) else {
        kernel::pr_err!("Failed to initialize EFI runtime\n");
        return -(bindings::ENOMEM as isize);
    };

    // SAFETY: efi_kexec_exit_boot_services() implements the ExitBootServices() prototype, and
    // is only ever called by the EFI image via the boot services table.
    let ebs: efiloader::bootservices::ExitBootServices = unsafe {
        core::mem::transmute(
            efi_kexec_exit_boot_services
                as unsafe extern "efiapi" fn(usize, usize) -> efiloader::status::Status,
        )
    };
    efi.override_exit_boot_services_handler(ebs);
    if efi.set_firmware_vendor("Linux kexec").is_err() {
        return -(bindings::ENOMEM as isize);
    }
    // SAFETY: the C side provides a dedicated stack in identity mapped memory
    unsafe { efi.set_image_stack(p.stack_top as *mut u8) };

    // SAFETY: guaranteed by the caller
    let tables = unsafe { core::slice::from_raw_parts(p.tables, p.nr_tables) };
    for t in tables {
        efi.install_configtable(&t.guid, t.table as *const ());
    }

    if p.initrd_size > 0 {
        efi.set_initrd_loader(MemFile {
            data: p.initrd,
            size: p.initrd_size,
        });
    }

    let image = MemFile {
        data: p.image,
        size: p.image_size,
    };
    let Some(li) = efi.load_image(&image) else {
        kernel::pr_err!("Failed to load EFI image\n");
        return -(bindings::ENOEXEC as isize);
    };
    // SAFETY: single threaded, see above
    let li = unsafe { &mut *IMAGE.0.get() }.insert(li);

    // SAFETY: guaranteed by the caller
    let cmdline = unsafe { core::slice::from_raw_parts(p.cmdline, p.cmdline_size) };
    let mut opts: Vec<u16> = core::str::from_utf8(cmdline)
        .unwrap_or("")
        .trim_end_matches('\0')
        .encode_utf16()
        .collect();
    opts.push(0);
    li.set_load_options(opts);

    p.systab = efi.system_table() as u64;

    let status = li.start_image();
    kernel::pr_err!(
        "EFI image returned {:?} without calling ExitBootServices()\n",
        status
    );
    -(bindings::ENOEXEC as isize)
}

/// Tear down the EFI runtime after the image has called ExitBootServices() or failed.
///
/// # Safety
///
/// Must be called with the identity map still installed, after efi_kexec_call() returned.
#[no_mangle]
unsafe extern "C" fn efi_kexec_teardown() {
    // SAFETY: efi_kexec_run() is no longer active
    drop(unsafe { &mut *IMAGE.0.get() }.take());
    // SAFETY: the image will never call into the EFI runtime again
    unsafe { efiloader::deinit() };
    // SAFETY: efi_kexec_run() is no longer active
    unsafe { *PARAMS.0.get() = ptr::null_mut() };
}
