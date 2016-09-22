/*
 * Copyright (C) 2016 Linaro Ltd. <ard.biesheuvel@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/efi.h>
#include <linux/io.h>
#include <linux/slab.h>

#include <asm/efi.h>

extern unsigned long mmc_fv_emulation_table;

enum emmc_state {
	mmc_invalid_state = 0,
	mmc_hw_initialization_state,
	mmc_idle_state,
	mmc_ready_state,
	mmc_identification_state,
	mmc_standby_state,
	mmc_transfer_state,
	mmc_sending_data_state,
	mmc_receive_data_state,
	mmc_programming_state,
	mmc_disconnect_state,
};

static char const emmc_state_string[][28] = {
	"mmc_invalid_state",
	"mmc_hw_initialization_state",
	"mmc_idle_state",
	"mmc_ready_state",
	"mmc_identification_state",
	"mmc_standby_state",
	"mmc_transfer_state",
	"mmc_sending_data_state",
	"mmc_receive_data_state",
	"mmc_programming_state",
	"mmc_disconnect_state",
};

/*
 * This MMC host protocol version is not in the UEFI spec, and lives under
 * EmbeddedPkg/ in Tianocore/EDK2.
 */
struct emmc_host_protocol
{
	u32		revision;
	bool		(*is_card_present)(struct emmc_host_protocol*);
	bool		(*is_read_only)(struct emmc_host_protocol*);
	efi_status_t	(*build_device_path)(struct emmc_host_protocol*,
					     void*);
	efi_status_t	(*notify_state)(struct emmc_host_protocol*,
					enum emmc_state);
	efi_status_t	(*send_command)(struct emmc_host_protocol*,
					u32, u32);
	efi_status_t	(*receive_response)(struct emmc_host_protocol*,
					    u32, u32*);
	efi_status_t	(*read_block_data)(struct emmc_host_protocol*,
					   u64, unsigned long, u32*);
	efi_status_t	(*write_block_data)(struct emmc_host_protocol*,
					    u64, unsigned long, u32*);
};

static bool mmc_is_card_present(struct emmc_host_protocol *this)
{
	return true;
}

static bool mmc_is_read_only(struct emmc_host_protocol *this)
{
	return false;
}

static efi_status_t mmc_build_device_path(struct emmc_host_protocol *this,
					  void *dpp)
{
	return EFI_UNSUPPORTED;
}

static efi_status_t mmc_notify_state(struct emmc_host_protocol *this,
				     enum emmc_state state)
{
	struct efi_simd_reg_stash simd_stash;

	arch_efi_stash_simd_regs(&simd_stash);
	arch_efi_call_virt_teardown();

	pr_warn("mmc-proxy: entered %s state\n", emmc_state_string[state]);
	might_sleep();

	arch_efi_call_virt_setup();
	arch_efi_unstash_simd_regs(&simd_stash);

	return EFI_SUCCESS;
}

static efi_status_t mmc_send_command(struct emmc_host_protocol *this, u32 cmd,
				     u32 arg)
{
	struct efi_simd_reg_stash simd_stash;

	arch_efi_stash_simd_regs(&simd_stash);
	arch_efi_call_virt_teardown();

	pr_warn("mmc-proxy: send command %d (0x%x)\n", cmd, arg);
	might_sleep();

	arch_efi_call_virt_setup();
	arch_efi_unstash_simd_regs(&simd_stash);
	return EFI_NOT_FOUND;
}

static efi_status_t mmc_receive_response(struct emmc_host_protocol *this,
					 u32 mmc_response_type, u32 *buffer)
{
	struct efi_simd_reg_stash simd_stash;
	u32 response[4] = {};

	arch_efi_stash_simd_regs(&simd_stash);
	arch_efi_call_virt_teardown();

	pr_warn("mmc-proxy: receive response %d\n", mmc_response_type);
	might_sleep();

	arch_efi_call_virt_setup();
	arch_efi_unstash_simd_regs(&simd_stash);
	memcpy(buffer, response, sizeof(response));

	return EFI_NOT_FOUND;
}

static efi_status_t mmc_read_block_data(struct emmc_host_protocol *this,
					u64 lba, unsigned long len,
					u32 *buffer)
{
	struct efi_simd_reg_stash simd_stash;
	void *bounce;

	arch_efi_stash_simd_regs(&simd_stash);
	arch_efi_call_virt_teardown();

	bounce = kmalloc(len, GFP_KERNEL);

	pr_warn("mmc-proxy: read block data lba==%lld, len==%ld\n", lba, len);
	might_sleep();

	arch_efi_call_virt_setup();
	arch_efi_unstash_simd_regs(&simd_stash);
	memcpy(buffer, bounce, len);
	kfree(bounce);

	return EFI_NOT_FOUND;
}

static efi_status_t mmc_write_block_data(struct emmc_host_protocol *this,
					 u64 lba, unsigned long len,
					 u32 *buffer)
{
	struct efi_simd_reg_stash simd_stash;
	void *bounce;

	/*
	 * 'buffer' may point to memory that is mapped via the EFI page tables,
	 * so copy the data before switching back to the ordinary mappings.
	 */
	bounce = kmalloc(len, GFP_ATOMIC);
	if (!bounce)
		return EFI_OUT_OF_RESOURCES;
	memcpy(bounce, buffer, len);

	arch_efi_stash_simd_regs(&simd_stash);
	arch_efi_call_virt_teardown();

	pr_warn("mmc-proxy: write block data lba==%lld, len==%ld\n", lba, len);
	might_sleep();

	kfree(bounce);
	arch_efi_call_virt_setup();
	arch_efi_unstash_simd_regs(&simd_stash);
	return EFI_NOT_FOUND;
}

static const struct emmc_host_protocol emmc_proxy =
{
	0x00010001,		// revision 1.1
	mmc_is_card_present,
	mmc_is_read_only,
	mmc_build_device_path,
	mmc_notify_state,
	mmc_send_command,
	mmc_receive_response,
	mmc_read_block_data,
	mmc_write_block_data
};

static int __init emmc_proxy_install(void)
{
	unsigned long *p;

	if (mmc_fv_emulation_table == EFI_INVALID_TABLE_ADDR)
		return 0;

	p = memremap(mmc_fv_emulation_table, sizeof(*p), MEMREMAP_WB);
	if (!p)
		return -ENOMEM;

	/*
	 * We expect a NULL value here, since the firmware should have cleared
	 * this value in its ExitBootServices() handler.
	 */
	if (!WARN_ON(*p != 0))
		*p = (unsigned long)&emmc_proxy;

	memunmap(p);
	return 0;
}
late_initcall(emmc_proxy_install);
