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
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/uaccess.h>

#include <asm/kaiser.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/desc.h>

/*
 * At runtime, the only things we map are some things for CPU
 * hotplug, and stacks for new processes.  No two CPUs will ever
 * be populating the same addresses, so we only need to ensure
 * that we protect between two CPUs trying to allocate and
 * populate the same page table page.
 *
 * Only take this lock when doing a set_p[4um]d(), but it is not
 * needed for doing a set_pte().  We assume that only the *owner*
 * of a given allocation will be doing this for _their_
 * allocation.
 *
 * This ensures that once a system has been running for a while
 * and there have been stacks all over and these page tables
 * are fully populated, there will be no further acquisitions of
 * this lock.
 */
static DEFINE_SPINLOCK(shadow_table_allocation_lock);

/*
 * Returns -1 on error.
 */
static inline unsigned long get_pa_from_mapping(unsigned long vaddr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset_k(vaddr);
	/*
	 * We made all the kernel PGDs present in kaiser_init().
	 * We expect them to stay that way.
	 */
	if (pgd_none(*pgd)) {
		WARN_ON_ONCE(1);
		return -1;
	}
	/*
	 * PGDs are either 512GB or 128TB on all x86_64
	 * configurations.  We don't handle these.
	 */
	if (pgd_large(*pgd)) {
		WARN_ON_ONCE(1);
		return -1;
	}

	p4d = p4d_offset(pgd, vaddr);
	if (p4d_none(*p4d)) {
		WARN_ON_ONCE(1);
		return -1;
	}

	pud = pud_offset(p4d, vaddr);
	if (pud_none(*pud)) {
		WARN_ON_ONCE(1);
		return -1;
	}

	if (pud_large(*pud))
		return (pud_pfn(*pud) << PAGE_SHIFT) | (vaddr & ~PUD_PAGE_MASK);

	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd)) {
		WARN_ON_ONCE(1);
		return -1;
	}

	if (pmd_large(*pmd))
		return (pmd_pfn(*pmd) << PAGE_SHIFT) | (vaddr & ~PMD_PAGE_MASK);

	pte = pte_offset_kernel(pmd, vaddr);
	if (pte_none(*pte)) {
		WARN_ON_ONCE(1);
		return -1;
	}

	return (pte_pfn(*pte) << PAGE_SHIFT) | (vaddr & ~PAGE_MASK);
}

#define KAISER_NO_FLAGS		0
#define KAISER_WALK_ATOMIC	0x1
#define KAISER_WALK_NO_ALLOC	0x2

/*
 * This is a relatively normal page table walk, except that it
 * only walks the shadow page tables and can try to allocate
 * new page tables pages along the way.
 *
 * Returns a pointer to a PTE on success, or NULL on failure.
 */
static pte_t *kaiser_pagetable_walk(unsigned long address, unsigned long flags)
{
	pmd_t *pmd;
	pud_t *pud;
	p4d_t *p4d;
	pgd_t *pgd = native_get_shadow_pgd(pgd_offset_k(address));
	gfp_t gfp = (GFP_KERNEL | __GFP_NOTRACK | __GFP_ZERO);

	might_sleep();
	if (flags & KAISER_WALK_ATOMIC) {
		gfp &= ~GFP_KERNEL;
		gfp |= __GFP_HIGH | __GFP_ATOMIC;
	}

	if (pgd_none(*pgd)) {
		WARN_ONCE(1, "All shadow pgds should have been populated");
		return NULL;
	}
	BUILD_BUG_ON(pgd_large(*pgd) != 0);

	p4d = p4d_offset(pgd, address);
	BUILD_BUG_ON(p4d_large(*p4d) != 0);
	if (p4d_none(*p4d)) {
		unsigned long new_pud_page;
		if (flags & KAISER_WALK_NO_ALLOC)
			return NULL;
		new_pud_page = __get_free_page(gfp);
		if (!new_pud_page)
			return NULL;

		spin_lock(&shadow_table_allocation_lock);
		if (p4d_none(*p4d))
			set_p4d(p4d, __p4d(_KERNPG_TABLE | __pa(new_pud_page)));
		else
			free_page(new_pud_page);
		spin_unlock(&shadow_table_allocation_lock);
	}

	pud = pud_offset(p4d, address);
	/* The shadow page tables do not use large mappings: */
	if (pud_large(*pud)) {
		WARN_ON(1);
		return NULL;
	}
	if (pud_none(*pud)) {
		unsigned long new_pmd_page;

		if (flags & KAISER_WALK_NO_ALLOC)
			return NULL;

		new_pmd_page = __get_free_page(gfp);
		if (!new_pmd_page)
			return NULL;

		spin_lock(&shadow_table_allocation_lock);
		if (pud_none(*pud))
			set_pud(pud, __pud(_KERNPG_TABLE | __pa(new_pmd_page)));
		else
			free_page(new_pmd_page);
		spin_unlock(&shadow_table_allocation_lock);
	}

	pmd = pmd_offset(pud, address);
	/* The shadow page tables do not use large mappings: */
	if (pmd_large(*pmd)) {
		WARN_ON(1);
		return NULL;
	}
	if (pmd_none(*pmd)) {
		unsigned long new_pte_page;

		if (flags & KAISER_WALK_NO_ALLOC)
			return NULL;

		new_pte_page = __get_free_page(gfp);
		if (!new_pte_page)
			return NULL;

		spin_lock(&shadow_table_allocation_lock);
		if (pmd_none(*pmd))
			set_pmd(pmd, __pmd(_KERNPG_TABLE  | __pa(new_pte_page)));
		else
			free_page(new_pte_page);
		spin_unlock(&shadow_table_allocation_lock);
	}

	return pte_offset_kernel(pmd, address);
}

/*
 * Given a kernel address, @__start_addr, copy that mapping into
 * the user (shadow) page tables.  This may need to allocate page
 * table pages.
 */
int kaiser_add_user_map(const void *__start_addr, unsigned long size,
			unsigned long flags)
{
	pte_t *pte;
	unsigned long start_addr = (unsigned long)__start_addr;
	unsigned long address = start_addr & PAGE_MASK;
	unsigned long end_addr = PAGE_ALIGN(start_addr + size);
	unsigned long target_address;

	for (; address < end_addr; address += PAGE_SIZE) {
		target_address = get_pa_from_mapping(address);
		if (target_address == -1)
			return -EIO;

		pte = kaiser_pagetable_walk(address, KAISER_NO_FLAGS);
		/*
		 * Errors come from either -ENOMEM for a page
		 * table page, or something screwy that did a
		 * WARN_ON().  Just return -ENOMEM.
		 */
		if (!pte)
			return -ENOMEM;
		if (pte_none(*pte)) {
			set_pte(pte, __pte(flags | target_address));
		} else {
			pte_t tmp;
			set_pte(&tmp, __pte(flags | target_address));
			WARN_ON_ONCE(!pte_same(*pte, tmp));
		}
	}
	return 0;
}

int kaiser_add_user_map_ptrs(const void *__start_addr,
			     const void *__end_addr,
			     unsigned long flags)
{
	return kaiser_add_user_map(__start_addr,
				   __end_addr - __start_addr,
				   flags);
}

static int kaiser_user_map_ptr_early(const void *start_addr, unsigned long size,
				 unsigned long flags)
{
	int ret = kaiser_add_user_map(start_addr, size, flags);
	WARN_ON(ret);
	return ret;
}

/*
 * Ensure that the top level of the (shadow) page tables are
 * entirely populated.  This ensures that all processes that get
 * forked have the same entries.  This way, we do not have to
 * ever go set up new entries in older processes.
 *
 * Note: we never free these, so there are no updates to them
 * after this.
 */
static void __init kaiser_init_all_pgds(void)
{
	pgd_t *pgd;
	int i = 0;

	pgd = native_get_shadow_pgd(pgd_offset_k(0UL));
	for (i = PTRS_PER_PGD / 2; i < PTRS_PER_PGD; i++) {
		unsigned long addr = PAGE_OFFSET + i * PGDIR_SIZE;
#if CONFIG_PGTABLE_LEVELS > 4
		p4d_t *p4d = p4d_alloc_one(&init_mm, addr);
		if (!p4d) {
			WARN_ON(1);
			break;
		}
		pgd[i] = __pgd(_KERNPG_TABLE | __pa(p4d));
#else /* CONFIG_PGTABLE_LEVELS <= 4 */
		pud_t *pud = pud_alloc_one(&init_mm, addr);
		if (!pud) {
			WARN_ON(1);
			break;
		}
		pgd[i] = __pgd(_KERNPG_TABLE | __pa(pud));
#endif /* CONFIG_PGTABLE_LEVELS */
	}
}

/*
 * The page table allocations in here can theoretically fail, but
 * we can not do much about it in early boot.  Do the checking
 * and warning in a macro to make it more readable.
 */
#define kaiser_add_user_map_early(start, size, flags) do {	\
	int __ret = kaiser_add_user_map(start, size, flags);	\
	WARN_ON(__ret);						\
} while (0)

#define kaiser_add_user_map_ptrs_early(start, end, flags) do {		\
	int __ret = kaiser_add_user_map_ptrs(start, end, flags);	\
	WARN_ON(__ret);							\
} while (0)

extern char __per_cpu_user_mapped_start[], __per_cpu_user_mapped_end[];
/*
 * If anything in here fails, we will likely die on one of the
 * first kernel->user transitions and init will die.  But, we
 * will have most of the kernel up by then and should be able to
 * get a clean warning out of it.  If we BUG_ON() here, we run
 * the risk of being before we have good console output.
 */
static int kaiser_init_finished = 0;
void kaiser_check_idt_table(const struct desc_ptr *idt_desc);
void __init kaiser_init(void)
{
	int cpu;

	kaiser_init_all_pgds();

	for_each_possible_cpu(cpu) {
		void *percpu_vaddr = __per_cpu_user_mapped_start +
				     per_cpu_offset(cpu);
		unsigned long percpu_sz = __per_cpu_user_mapped_end -
					  __per_cpu_user_mapped_start;
		kaiser_add_user_map_early(percpu_vaddr, percpu_sz,
					  __PAGE_KERNEL);
	}

	kaiser_add_user_map_ptrs_early(__entry_text_start, __entry_text_end,
				       __PAGE_KERNEL_RX);

	/* the fixed map address of the idt_table */
	kaiser_add_user_map_early((void *)idt_descr.address,
				  sizeof(gate_desc) * NR_VECTORS,
				  __PAGE_KERNEL_RO);

	kaiser_user_map_ptr_early(&debug_idt_table,
				  sizeof(gate_desc) * NR_VECTORS,
				  __PAGE_KERNEL);

	/*
	 * We could theoretically do this in setup_fixmap_gdt().
	 * But, we would need to rewrite the above page table
	 * allocation code to use the bootmem allocator.  The
	 * buddy allocator is not available at the time that we
	 * call setup_fixmap_gdt() for CPU 0.
	 */
	kaiser_add_user_map_early(get_cpu_gdt_ro(0), PAGE_SIZE,
				  __PAGE_KERNEL_RO);

	/*
	 * .irqentry.text helps us identify code that runs before
	 * we get a chance to call entering_irq().  This includes
	 * the interrupt entry assembly plus the first C function
	 * that gets called.  KAISER does not need the C code
	 * mapped.  We just use the .irqentry.text section as-is
	 * to avoid having to carve out a new section for the
	 * assembly only.
	 */
	kaiser_add_user_map_ptrs_early(__irqentry_text_start,
				       __irqentry_text_end,
				       __PAGE_KERNEL_RX);

	kaiser_init_finished = 1;
	kaiser_check_idt_table(&idt_descr);
	kaiser_check_idt_table(&debug_idt_descr);
}

extern void unmap_pud_range_nofree(pgd_t *pgd, unsigned long start,
				   unsigned long end);
int kaiser_add_mapping(unsigned long addr, unsigned long size,
		       unsigned long flags)
{
	return kaiser_add_user_map((const void *)addr, size, flags);
}

void kaiser_remove_mapping(unsigned long start, unsigned long size)
{
	unsigned long end = start + size;
	unsigned long addr;

	for (addr = start; addr < end; addr += PGDIR_SIZE) {
		pgd_t *pgd = native_get_shadow_pgd(pgd_offset_k(addr));
		/*
		 * unmap_p4d_range() handles > P4D_SIZE unmaps,
		 * so no need to trim 'end'.
		 */
		unmap_pud_range_nofree(pgd, addr, end);
	}
}

/*
 * If we fail to map something, it is not fun to debug because it
 * will often crash in the entry code, which jumps into the entry
 * code.  To catch these problems, allow the kaiser mappings to
 * be checked before we actually need to use them.
 */
void kaiser_check_user_mapped(const void *addr)
{
	pte_t *pte;

	/*
	 * idt_setup_early_handler() might call in here before
	 * kaiser_init() runs.  Ignore those calls.
	 */
	if (!kaiser_init_finished)
		return;

	pte = kaiser_pagetable_walk((unsigned long)addr, KAISER_WALK_NO_ALLOC);

	if (pte && pte_present(*pte))
		return;

	WARN(1, "address is not mapped into user page tables: %pK\n", addr);
}

void kaiser_check_idt_table(const struct desc_ptr *idt_desc)
{
	struct gate_struct *hw_table_ptr;
	int table_nr_entries;
	int i;

	/*
	 * Note: "idt_desc" itself is not user-mapped.  The
	 * descriptor's content are loaded into a register and it
	 * is not referenced after the 'lidt' instruction used to
	 * load its contents.
	 */

	hw_table_ptr = (struct gate_struct *)idt_desc->address;
	/* The hardware description in 'idt_desc->size' is in bytes. */
	table_nr_entries = idt_desc->size / sizeof(*hw_table_ptr);

	for (i = 0; i < table_nr_entries; i++) {
		struct gate_struct *hw_table_entry = &hw_table_ptr[i];
		void *idt_handler_addr = (void *)gate_offset(hw_table_entry);

		/* Make sure the table itself is mapped: */
		kaiser_check_user_mapped(hw_table_entry);

		/* Skip empty entries */
		if (!idt_handler_addr)
			continue;
		/*
		 * Entries for the early IDT handlers are left in
		 * the IDT even after boot.  They are not used
		 * and are not user-mapped, so skip the checks
		 * for them.
		 */
		if (!test_bit(i, used_vectors))
			continue;

		kaiser_check_user_mapped(idt_handler_addr);
	}
}
