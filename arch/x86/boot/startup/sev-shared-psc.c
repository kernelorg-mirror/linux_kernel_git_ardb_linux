void __noreturn
sev_es_terminate(unsigned int set, unsigned int reason)
{
	u64 val = GHCB_MSR_TERM_REQ;

	/* Tell the hypervisor what went wrong. */
	val |= GHCB_SEV_TERM_REASON(set, reason);

	/* Request Guest Termination from Hypervisor */
	sev_es_wr_ghcb_msr(val);
	VMGEXIT();

	while (true)
		asm volatile("hlt\n" : : : "memory");
}

int svsm_process_result_codes(struct svsm_call *call)
{
	switch (call->rax_out) {
	case SVSM_SUCCESS:
		return 0;
	case SVSM_ERR_INCOMPLETE:
	case SVSM_ERR_BUSY:
		return -EAGAIN;
	default:
		return -EINVAL;
	}
}

/*
 * Issue a VMGEXIT to call the SVSM:
 *   - Load the SVSM register state (RAX, RCX, RDX, R8 and R9)
 *   - Set the CA call pending field to 1
 *   - Issue VMGEXIT
 *   - Save the SVSM return register state (RAX, RCX, RDX, R8 and R9)
 *   - Perform atomic exchange of the CA call pending field
 *
 *   - See the "Secure VM Service Module for SEV-SNP Guests" specification for
 *     details on the calling convention.
 *     - The calling convention loosely follows the Microsoft X64 calling
 *       convention by putting arguments in RCX, RDX, R8 and R9.
 *     - RAX specifies the SVSM protocol/callid as input and the return code
 *       as output.
 */
void svsm_issue_call(struct svsm_call *call, u8 *pending)
{
	register unsigned long rax asm("rax") = call->rax;
	register unsigned long rcx asm("rcx") = call->rcx;
	register unsigned long rdx asm("rdx") = call->rdx;
	register unsigned long r8  asm("r8")  = call->r8;
	register unsigned long r9  asm("r9")  = call->r9;

	call->caa->call_pending = 1;

	asm volatile("rep; vmmcall\n\t"
		     : "+r" (rax), "+r" (rcx), "+r" (rdx), "+r" (r8), "+r" (r9)
		     : : "memory");

	*pending = xchg(&call->caa->call_pending, *pending);

	call->rax_out = rax;
	call->rcx_out = rcx;
	call->rdx_out = rdx;
	call->r8_out  = r8;
	call->r9_out  = r9;
}

int svsm_perform_msr_protocol(struct svsm_call *call)
{
	u8 pending = 0;
	u64 val, resp;

	/*
	 * When using the MSR protocol, be sure to save and restore
	 * the current MSR value.
	 */
	val = sev_es_rd_ghcb_msr();

	sev_es_wr_ghcb_msr(GHCB_MSR_VMPL_REQ_LEVEL(0));

	svsm_issue_call(call, &pending);

	resp = sev_es_rd_ghcb_msr();

	sev_es_wr_ghcb_msr(val);

	if (pending)
		return -EINVAL;

	if (GHCB_RESP_CODE(resp) != GHCB_MSR_VMPL_RESP)
		return -EINVAL;

	if (GHCB_MSR_VMPL_RESP_VAL(resp))
		return -EINVAL;

	return svsm_process_result_codes(call);
}

static int svsm_call_msr_protocol(struct svsm_call *call)
{
	int ret;

	do {
		ret = svsm_perform_msr_protocol(call);
	} while (ret == -EAGAIN);

	return ret;
}

static void svsm_pval_4k_page(unsigned long paddr, bool validate,
			      struct svsm_ca *caa, u64 caa_pa)
{
	struct svsm_pvalidate_call *pc;
	struct svsm_call call = {};
	unsigned long flags;
	u64 pc_pa;

	/*
	 * This can be called very early in the boot, use native functions in
	 * order to avoid paravirt issues.
	 */
	flags = native_local_irq_save();

	call.caa = caa;

	pc = (struct svsm_pvalidate_call *)call.caa->svsm_buffer;
	pc_pa = caa_pa + offsetof(struct svsm_ca, svsm_buffer);

	pc->num_entries = 1;
	pc->cur_index   = 0;
	pc->entry[0].page_size = RMP_PG_SIZE_4K;
	pc->entry[0].action    = validate;
	pc->entry[0].ignore_cf = 0;
	pc->entry[0].rsvd      = 0;
	pc->entry[0].pfn       = paddr >> PAGE_SHIFT;

	/* Protocol 0, Call ID 1 */
	call.rax = SVSM_CORE_CALL(SVSM_CORE_PVALIDATE);
	call.rcx = pc_pa;

	/*
	 * Use the MSR protocol exclusively, so that this code is usable in
	 * startup code where VA/PA translations of the GHCB page's address may
	 * be problematic.
	 */
	if (svsm_call_msr_protocol(&call))
		sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_PVALIDATE);

	native_local_irq_restore(flags);
}

static void pvalidate_4k_page(unsigned long vaddr, unsigned long paddr,
			      bool validate, struct svsm_ca *caa, u64 caa_pa)
{
	int ret;

	if (snp_vmpl) {
		svsm_pval_4k_page(paddr, validate, caa, caa_pa);
	} else {
		ret = pvalidate(vaddr, RMP_PG_SIZE_4K, validate);
		if (ret)
			sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_PVALIDATE);
	}

	/*
	 * If validating memory (making it private) and affected by the
	 * cache-coherency vulnerability, perform the cache eviction mitigation.
	 */
	if (validate && sev_snp_needs_sfw)
		sev_evict_cache((void *)vaddr, 1);
}

static void __page_state_change(unsigned long vaddr, unsigned long paddr,
			        const struct psc_desc *desc)
{
	u64 val, msr;

	/*
	 * If private -> shared then invalidate the page before requesting the
	 * state change in the RMP table.
	 */
	if (desc->op == SNP_PAGE_STATE_SHARED)
		pvalidate_4k_page(vaddr, paddr, false, desc->ca, desc->caa_pa);

	/* Save the current GHCB MSR value */
	msr = sev_es_rd_ghcb_msr();

	/* Issue VMGEXIT to change the page state in RMP table. */
	sev_es_wr_ghcb_msr(GHCB_MSR_PSC_REQ_GFN(paddr >> PAGE_SHIFT, desc->op));
	VMGEXIT();

	/* Read the response of the VMGEXIT. */
	val = sev_es_rd_ghcb_msr();
	if ((GHCB_RESP_CODE(val) != GHCB_MSR_PSC_RESP) || GHCB_MSR_PSC_RESP_VAL(val))
		sev_es_terminate(SEV_TERM_SET_LINUX, GHCB_TERM_PSC);

	/* Restore the GHCB MSR value */
	sev_es_wr_ghcb_msr(msr);

	/*
	 * Now that page state is changed in the RMP table, validate it so that it is
	 * consistent with the RMP entry.
	 */
	if (desc->op == SNP_PAGE_STATE_PRIVATE)
		pvalidate_4k_page(vaddr, paddr, true, desc->ca, desc->caa_pa);
}

void snp_accept_memory(phys_addr_t start, phys_addr_t end)
{
	struct psc_desc d = {
		SNP_PAGE_STATE_PRIVATE,
		(struct svsm_ca *)boot_svsm_caa_pa,
		boot_svsm_caa_pa
	};

	for (phys_addr_t pa = start; pa < end; pa += PAGE_SIZE)
		__page_state_change(pa, pa, &d);
}
