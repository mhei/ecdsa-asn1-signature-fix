// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © 2023 Michael Heimpold <mhei@heimpold.de>
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "asn1.h"

int main(int argc, char *argv[])
{
	uint8_t buffer[1024];
	int l = 0, c;

	while (l < sizeof(buffer) &&
	       (c = getchar()) != EOF)
		buffer[l++] = c;

	c = asn1_fixup_ecdsa_signature(buffer);
	if (c == -1)
		return 1;

	l = c;

	for (c = 0; c < l; c++)
		printf("%c", buffer[c]);

	return 0;
}
