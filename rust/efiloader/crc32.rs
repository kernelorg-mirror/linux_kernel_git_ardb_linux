// SPDX-License-Identifier: GPL-2.0

//! CRC32 as used by the EFI table headers and the CalculateCrc32() boot service.
//!
//! The UEFI specification mandates the same CRC32 as used by zlib and Ethernet (reflected
//! polynomial 0xEDB88320, initial value and final XOR of all ones). The tables this is used on are
//! tiny, so a bitwise implementation is perfectly adequate.

pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}
