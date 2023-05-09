// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © 2023 Michael Heimpold <mhei@heimpold.de>
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "asn1.c"

int main(int argc, char *argv[])
{
	uint8_t in[] = { 0x30, 0x0a, 0x02, 0x03, 0x00, 0x00, 0x48, 0x02, 0x03, 0xff, 0xff, 0x9c };
	uint8_t out[] = { 0x30, 0x06, 0x02, 0x01, 0x48, 0x02, 0x01, 0x9c };
	int l;

	l = asn1_fixup_ecdsa_signature(in);
	if (l != sizeof(out)) {
		fprintf(stderr, "Size does not match expected one.\n");
		return 1;
	}

	if (memcmp(in, out, sizeof(out)) != 0) {
		fprintf(stderr, "Output does not match expected one.\n");
		return 1;
	}

	return 0;
}
