/* ALIAS-DIFF round-2 opaque TU: provides a function whose body is invisible
 * to the optimizer at the call site, forcing it to assume the function
 * may modify any pointer-aliased storage.
 *
 * Compiled separately (no LTO) so the caller's optimizer cannot inline or
 * constant-fold through the function.  The function takes a uint32_t by
 * value and returns a uint32_t; the body does a compiler-builtin memory
 * clobber and a few arithmetic ops so its return value is genuinely
 * opaque to the caller.
 */
#include <stdint.h>

uint32_t opaque_ext(uint32_t x) {
    /* Clobber memory: caller cannot assume any pointer it passes or
     * any global state it accesses is unchanged across this call. */
    __asm__ volatile("" : : "r"(x) : "memory");
    /* Some arithmetic to make the return value depend on x in a way
     * the caller's optimizer can verify does not get constant-folded
     * (because the memory clobber is opaque to it). */
    x ^= (x << 13);
    x ^= (x >> 17);
    x ^= (x << 5);
    return x;
}

void touch_ext(volatile void *p) {
    __asm__ volatile("" : : "r"(p) : "memory");
}
