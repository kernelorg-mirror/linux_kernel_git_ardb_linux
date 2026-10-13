# efiloader

This is the `efiloader` crate, which implements a minimal EFI boot services
environment that is sufficient to load and start EFI executables such as EFI
stub Linux kernels, EFI zboot images and systemd-boot UKIs.

It is used by the arm64 kexec loader for EFI images (`CONFIG_KEXEC_EFI_STUB`,
see `arch/arm64/kernel/kexec_efi.c`), which runs the incoming kernel's EFI stub
at `kexec_file_load()` time, up to the point where it calls `ExitBootServices()`.

Upstream: https://github.com/ardbiesheuvel/efiloader (commit 0b409661216e,
plus the fixes series ending at commit e30d070a4525, which has not been merged
upstream yet)

Like upstream, the crate is built as Rust 2024 edition code.

## Changes compared to upstream

- The crates.io dependencies have been replaced by small in-crate modules or
  kernel facilities:
  - `log` by a minimal facade (`log.rs`) whose output is routed to `printk()`
    by the embedder;
  - `crc` by a bitwise CRC32 (`crc32.rs`), implementing the zlib/ISO-HDLC
    CRC32 that UEFI requires;
  - `widestring` and `const-utf16` by `utf16.rs`;
  - `linked_list_allocator` by a minimal first fit heap (`heap.rs`);
  - `once_cell` by a resettable `UnsafeCell` holder, as the EFI context needs
    to be instantiated and torn down for each image that is loaded (`init()`
    and the new `deinit()`). Both are unsafe functions, as their callers must
    serialize them with each other and with all other uses of the EFI runtime.
- `kernel_alloc.rs` provides the global allocator shim expected by the `alloc`
  crate, as the kernel is not linked by rustc.
- New embedder hooks: `override_exit_boot_services_handler()`, `memmap_key()`,
  `system_table()`, `set_runtime_services_table()`, `set_firmware_vendor()`,
  `set_image_stack()`, `context()` and `MemoryMap::declare_typed_region()`.
- Images started by other images run on the stack provided via
  `set_image_stack()` as well, below the frames of the image that started them.
  The `start_image()` assembler helpers stay on the current stack for this
  purpose when they are passed a NULL stack pointer.
- BTI landing pads for the indirectly called assembler wrappers.
- The assembler sources were renamed from `.s` to `.S`, as the kernel treats
  `*.s` files as build artifacts.
