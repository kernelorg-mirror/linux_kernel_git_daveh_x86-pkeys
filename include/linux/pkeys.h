#ifndef _LINUX_PKEYS_H
#define _LINUX_PKEYS_H

#include <linux/mm_types.h>
#include <asm/mmu_context.h>

#ifdef CONFIG_ARCH_HAS_PKEYS
#include <asm/pkeys.h>
#else /* ! CONFIG_ARCH_HAS_PKEYS */

/*
 * This is called from mprotect_pkey().
 *
 * Returns true if the protection keys is valid.
 */
static inline bool arch_validate_pkey(int key)
{
	return true;
}
#endif /* ! CONFIG_ARCH_HAS_PKEYS */

#endif /* _LINUX_PKEYS_H */
