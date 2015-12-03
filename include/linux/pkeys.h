#ifndef _LINUX_PKEYS_H
#define _LINUX_PKEYS_H

#include <linux/mm_types.h>

#ifdef CONFIG_ARCH_HAS_PKEYS
#include <asm/pkeys.h>
#include <asm/mmu_context.h>
#else /* ! CONFIG_ARCH_HAS_PKEYS */
#define ARCH_VM_PKEY_FLAGS 0

/*
 * This is called from mprotect_pkey().
 *
 * Returns true if the protection keys is valid.
 */
static inline bool arch_validate_pkey(int key)
{
	return true;
}

static inline int vma_pkey(struct vm_area_struct *vma)
{
	return 0;
}

static inline bool mm_pkey_is_allocated(struct mm_struct *mm, int pkey)
{
	return (pkey == 0);
}

static inline int mm_pkey_alloc(struct mm_struct *mm)
{
	return -1;
}

static inline int mm_pkey_free(struct mm_struct *mm, int pkey)
{
	WARN_ONCE(1, "free of protection key when disabled");
	return -EINVAL;
}

static inline int arch_set_user_pkey_access(struct task_struct *tsk, int pkey,
			unsigned long init_val)
{
	return 0;
}

#endif /* ! CONFIG_ARCH_HAS_PKEYS */

#endif /* _LINUX_PKEYS_H */
