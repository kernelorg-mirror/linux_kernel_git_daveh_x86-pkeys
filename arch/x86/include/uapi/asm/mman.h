#ifndef _ASM_X86_MMAN_H
#define _ASM_X86_MMAN_H

#define MAP_32BIT	0x40		/* only give out 32bit addresses */

#define MAP_HUGE_2MB    (21 << MAP_HUGE_SHIFT)
#define MAP_HUGE_1GB    (30 << MAP_HUGE_SHIFT)

#include <asm-generic/mman.h>

#ifndef arch_validate_prot
/*
 * This is called from mprotect().  PROT_GROWSDOWN and PROT_GROWSUP have
 * already been masked out.
 *
 * Returns true if the prot flags are valid
 */
#define arch_validate_prot(prot) (\
	(prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM |	\
	 PROT_PKEY0 | PROT_PKEY1 | PROT_PKEY2 | PROT_PKEY3)) == 0)	\

#endif


#endif /* _ASM_X86_MMAN_H */
