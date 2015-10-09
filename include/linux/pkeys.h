#ifndef _LINUX_PKEYS_H
#define _LINUX_PKEYS_

#include <linux/mm_types.h>
#include <asm/mmu_context.h>

/*
 * Key 0 is special.  Always make it appear allocated.
 */
#ifndef mm_pkey_allocation_map
#define mm_pkey_allocation_map(mm)	0x1
#define mm_set_pkey_allocated(mm, pkey) do{}while(0)
#define mm_set_pkey_free(mm, pkey) do{}while(0)
#endif

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
	if (mm_pkey_allocation_map(mm) == all_pkeys_mask) {
		trace_printk("%s() all keys allocated\n", __func__);
		return -1;
	}

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

#endif /* _LINUX_PKEYS_H */
