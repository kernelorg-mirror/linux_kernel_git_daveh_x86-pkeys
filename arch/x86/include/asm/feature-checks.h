#ifndef _ASM_X86_FEATURE_CHECKS_H
#define _ASM_X86_FEATURE_CHECKS_H

/*
 *
 */

static inline bool __init sse2_usable(void)
{
	if (!cpu_has_xfeatures(XFEATURE_MASK_SSE | XFEATURE_MASK_YMM, NULL))
		return false;
	return true;
}

static inline bool __init avx_usable(void)
{
	if (!sse2_usable())
		return false;
	if (!cpu_has_avx || !cpu_has_osxsave)
		return false;
	return true;
}

static inline bool __init avx2_usable(void)
{
       if (avx_usable() && cpu_has_avx2)
               return true;

       return false;
}

#endif /* _ASM_X86_FEATURE_CHECKS_H */
