#ifndef _ASM_X86_PKEYS_H
#define _ASM_X86_PKEYS_H

#define arch_max_pkey() (boot_cpu_has(X86_FEATURE_OSPKE) ?      \
				CONFIG_NR_PROTECTION_KEYS : 1)
#define arch_validate_pkey(pkey) (((pkey) >= 0) && ((pkey) < arch_max_pkey()))

#define ARCH_VM_PKEY_FLAGS (VM_PKEY_BIT0 | VM_PKEY_BIT1 | VM_PKEY_BIT2 | VM_PKEY_BIT3)

#define mm_pkey_allocation_map(mm)	(mm->context.pkey_allocation_map)
#define mm_set_pkey_allocated(mm, pkey) do {		\
	mm_pkey_allocation_map(mm) |= (1 << pkey);	\
} while (0)
#define mm_set_pkey_free(mm, pkey) do {			\
	mm_pkey_allocation_map(mm) &= ~(1 << pkey);	\
} while (0)

static inline
bool mm_pkey_is_allocated(struct mm_struct *mm, unsigned long pkey)
{
	if (!arch_validate_pkey(pkey))
		return true;

	return mm_pkey_allocation_map(mm) & (1 << pkey);
}

static inline
int mm_pkey_alloc(struct mm_struct *mm)
{
	int all_pkeys_mask = ((1 << arch_max_pkey()) - 1);
	int ret;

	/*
	 * Are we out of pkeys?  We must handle this specially
	 * because ffz() behavior is undefined if there are no
	 * zeros.
	 */
	if (mm_pkey_allocation_map(mm) == all_pkeys_mask)
		return -1;

	ret = ffz(mm_pkey_allocation_map(mm));

	mm_set_pkey_allocated(mm, ret);

	return ret;
}

static inline
int mm_pkey_free(struct mm_struct *mm, int pkey)
{
	/*
	 * pkey 0 is special, always allocated and can never
	 * be freed.
	 */
	if (!pkey || !arch_validate_pkey(pkey))
		return -EINVAL;
	if (!mm_pkey_is_allocated(mm, pkey))
		return -EINVAL;

	mm_set_pkey_free(mm, pkey);

	return 0;
}

#endif /*_ASM_X86_PKEYS_H */


