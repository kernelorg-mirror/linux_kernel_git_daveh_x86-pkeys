#undef TRACE_SYSTEM
#define TRACE_SYSTEM mpx

#if !defined(_TRACE_MPX_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_MPX_H

#include <linux/tracepoint.h>

#ifdef CONFIG_X86_INTEL_MPX

TRACE_EVENT(bounds_exception_mpx,

	TP_PROTO(struct bndcsr *bndcsr),
	TP_ARGS(bndcsr),

	TP_STRUCT__entry(
		__field(u64, bndcfgu)
		__field(u64, bndstatus)
	),

	TP_fast_assign(
		__entry->bndcfgu   = bndcsr->bndcfgu;
		__entry->bndstatus = bndcsr->bndstatus;
	),

	TP_printk("bndcfgu:0x%llx bndstatus:0x%llx",
		__entry->bndcfgu,
		__entry->bndstatus)
);

#else

/*
 * This gets used outside of MPX-specific code, so we need a stub.
 */
static inline void trace_bounds_exception_mpx(struct bndcsr *bndcsr)
{
}

#endif /* CONFIG_X86_INTEL_MPX */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH asm/trace/
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE mpx
#endif /* _TRACE_MPX_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
