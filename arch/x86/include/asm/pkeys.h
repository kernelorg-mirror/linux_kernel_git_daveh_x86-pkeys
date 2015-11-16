#ifndef _ASM_X86_PKEYS_H
#define _ASM_X86_PKEYS_H

#define arch_max_pkey() (boot_cpu_has(X86_FEATURE_OSPKE) ?      \
				CONFIG_NR_PROTECTION_KEYS : 1)
#define arch_validate_pkey(pkey) (((pkey) >= 0) && ((pkey) < arch_max_pkey()))

#endif /*_ASM_X86_PKEYS_H */


