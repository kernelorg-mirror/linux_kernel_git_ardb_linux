// SPDX-License-Identifier: GPL-2.0

#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <asm/pgtable_types.h>
#include <asm/sev.h>
#include <asm/msr-index.h>

u8 snp_vmpl;
u64 boot_svsm_caa_pa;

/*
 * SNP_FEATURES_IMPL_REQ is the mask of SNP features that will need
 * guest side implementation for proper functioning of the guest. If any
 * of these features are enabled in the hypervisor but are lacking guest
 * side implementation, the behavior of the guest will be undefined. The
 * guest could fail in non-obvious way making it difficult to debug.
 *
 * As the behavior of reserved feature bits is unknown to be on the
 * safe side add them to the required features mask.
 */
#define SNP_FEATURES_IMPL_REQ	(MSR_AMD64_SNP_VTOM |			\
				 MSR_AMD64_SNP_REFLECT_VC |		\
				 MSR_AMD64_SNP_RESTRICTED_INJ |		\
				 MSR_AMD64_SNP_ALT_INJ |		\
				 MSR_AMD64_SNP_DEBUG_SWAP |		\
				 MSR_AMD64_SNP_VMPL_SSS |		\
				 MSR_AMD64_SNP_SECURE_TSC |		\
				 MSR_AMD64_SNP_VMGEXIT_PARAM |		\
				 MSR_AMD64_SNP_VMSA_REG_PROT |		\
				 MSR_AMD64_SNP_RESERVED_BIT13 |		\
				 MSR_AMD64_SNP_RESERVED_BIT15 |		\
				 MSR_AMD64_SNP_SECURE_AVIC |		\
				 MSR_AMD64_SNP_RESERVED_MASK)

#ifdef CONFIG_AMD_SECURE_AVIC
#define SNP_FEATURE_SECURE_AVIC		MSR_AMD64_SNP_SECURE_AVIC
#else
#define SNP_FEATURE_SECURE_AVIC		0
#endif

/*
 * SNP_FEATURES_PRESENT is the mask of SNP features that are implemented
 * by the guest kernel. As and when a new feature is implemented in the
 * guest kernel, a corresponding bit should be added to the mask.
 */
#define SNP_FEATURES_PRESENT	(MSR_AMD64_SNP_DEBUG_SWAP |	\
				 MSR_AMD64_SNP_SECURE_TSC |	\
				 SNP_FEATURE_SECURE_AVIC)

u64 snp_get_unsupported_features(u64 status)
{
	if (!(status & MSR_AMD64_SEV_SNP_ENABLED))
		return 0;

	return status & SNP_FEATURES_IMPL_REQ & ~SNP_FEATURES_PRESENT;
}

/*
 * sev_check_cpu_support - Check for SEV support in the CPU capabilities
 *
 * Returns < 0 if SEV is not supported, otherwise the position of the
 * encryption bit in the page table descriptors.
 */
int sev_check_cpu_support(void)
{
	unsigned int eax, ebx, ecx, edx;

	/* Check for the SME/SEV support leaf */
	eax = 0x80000000;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if (eax < 0x8000001f)
		return -ENODEV;

	/*
	 * Check for the SME/SEV feature:
	 *   CPUID Fn8000_001F[EAX]
	 *   - Bit 0 - Secure Memory Encryption support
	 *   - Bit 1 - Secure Encrypted Virtualization support
	 *   CPUID Fn8000_001F[EBX]
	 *   - Bits 5:0 - Pagetable bit position used to indicate encryption
	 */
	eax = 0x8000001f;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	/* Check whether SEV is supported */
	if (!(eax & BIT(1)))
		return -ENODEV;

	sev_snp_needs_sfw = !(ebx & BIT(31));

	return ebx & 0x3f;
}

/*
 * sev_get_status - Retrieve the SEV status mask
 *
 * Returns 0 if the CPU is not SEV capable, otherwise the value of the
 * AMD64_SEV MSR.
 */
u64 sev_get_status(void)
{
	struct msr m;

	if (sev_check_cpu_support() < 0)
		return 0;

	raw_rdmsr(MSR_AMD64_SEV, &m);
	return m.q;
}

bool early_is_sevsnp_guest(void)
{
	static bool sevsnp;

	if (sevsnp)
		return true;

	if (!(sev_get_status() & MSR_AMD64_SEV_SNP_ENABLED))
		return false;

	sevsnp = true;

	if (!snp_vmpl) {
		unsigned int eax, ebx, ecx, edx;

		/*
		 * CPUID Fn8000_001F_EAX[28] - SVSM support
		 */
		eax = 0x8000001f;
		ecx = 0;
		native_cpuid(&eax, &ebx, &ecx, &edx);
		if (eax & BIT(28)) {
			struct msr m;

			/* Obtain the address of the calling area to use */
			raw_rdmsr(MSR_SVSM_CAA, &m);
			boot_svsm_caa_pa = m.q;

			/*
			 * The real VMPL level cannot be discovered, but the
			 * memory acceptance routines make no use of that so
			 * any non-zero value suffices here.
			 */
			snp_vmpl = U8_MAX;
		}
	}
	return true;
}
