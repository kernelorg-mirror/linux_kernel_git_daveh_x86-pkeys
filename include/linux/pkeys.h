#ifndef _LINUX_PKEYS_H
#define _LINUX_PKEYS_H

#include <linux/mm_types.h>
#include <asm/mmu_context.h>

#ifdef CONFIG_ARCH_HAS_PKEYS
#include <asm/pkeys.h>
#else /* ! CONFIG_ARCH_HAS_PKEYS */
#define arch_max_pkey() (1)
#define execute_only_pkey(mm) (0)
#define arch_override_mprotect_pkey(vma, prot, pkey) (0)
#define PKEY_DEDICATED_EXECUTE_ONLY 0
#define ARCH_VM_PKEY_FLAGS 0

/*
 * This is called from mprotect_pkey().
 *
 * Returns true if the protection keys is valid.
 */
static inline bool validate_pkey(int pkey)
{
	if (pkey < 0)
		return false;
	return (pkey < arch_max_pkey());
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
	return -EINVAL;
}

static inline
unsigned long arch_get_user_pkey_access(struct task_struct *tsk, int pkey)
{
	if (pkey)
		return -1;
	return 0;
}

#endif /* ! CONFIG_ARCH_HAS_PKEYS */

#endif /* _LINUX_PKEYS_H */
