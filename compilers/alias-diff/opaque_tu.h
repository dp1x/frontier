/* ALIAS-DIFF round-2 opaque TU public header. */
#ifndef ALIAS_DIFF_OPAQUE_TU_H
#define ALIAS_DIFF_OPAQUE_TU_H
#include <stdint.h>

/* Provided by opaque_tu.c; body invisible to the caller's optimizer
 * (separate TU, no LTO).  The function takes a uint32_t and returns
 * a uint32_t; the caller MUST treat the result as opaque. */
uint32_t opaque_ext(uint32_t x);

/* Memory clobber; the caller MUST treat any pointer-aliased storage
 * as modified across the call. */
void touch_ext(volatile void *p);

#endif
