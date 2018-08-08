/* Montgomery <-> Edwards isomorphism
 * Daniel Beer <dlbeer@gmail.com>, 18 Jan 2014
 *
 * This file is in the public domain.
 */

#ifndef MORPH25519_H_
#define MORPH25519_H_

#include <stdint.h>

/* Convert an Edwards Y to a Montgomery X (Edwards X is not used).
 * Resulting coordinate is normalized.
 */
void morph25519_e2m(uint8_t *montgomery_x, const uint8_t *edwards_y);

/* Return a parity bit for the Edwards X coordinate */
static inline int morph25519_eparity(const uint8_t *edwards_x)
{
	return edwards_x[0] & 1;
}

/* Convert a Montgomery X and a parity bit to an Edwards X/Y. Returns
 * non-zero if successful.
 */
uint8_t morph25519_m2e(uint8_t *ex, uint8_t *ey,
		       const uint8_t *mx, int parity);

#endif
