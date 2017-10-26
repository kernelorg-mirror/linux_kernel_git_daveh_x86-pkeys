#ifndef _ASM_X86_KAISER_H
#define _ASM_X86_KAISER_H
/*
 * Copyright(c) 2017 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Based on work published here: https://github.com/IAIK/KAISER
 * Modified by Dave Hansen <dave.hansen@intel.com to actually work.
 */
#ifndef __ASSEMBLY__

#ifdef CONFIG_KAISER
/**
 *  kaiser_add_mapping - map a virtual memory part to the shadow (user) mapping
 *  @addr: the start address of the range
 *  @size: the size of the range
 *  @flags: The mapping flags of the pages
 *
 *  The mapping is done on a global scope, so no bigger
 *  synchronization has to be done.  the pages have to be
 *  manually unmapped again when they are not needed any longer.
 */
extern int kaiser_add_mapping(unsigned long addr, unsigned long size,
			      unsigned long flags);

/**
 *  kaiser_remove_mapping - unmap a virtual memory part of the shadow mapping
 *  @addr: the start address of the range
 *  @size: the size of the range
 */
extern void kaiser_remove_mapping(unsigned long start, unsigned long size);

/**
 *  kaiser_initialize_mapping - Initialize the shadow mapping
 *
 *  Most parts of the shadow mapping can be mapped upon boot
 *  time.  Only per-process things like the thread stacks
 *  or a new LDT have to be mapped at runtime.  These boot-
 *  time mappings are permanent and nevertunmapped.
 */
extern void kaiser_init(void);

void kaiser_check_user_mapped(const void *addr);

#endif

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_KAISER_H */
