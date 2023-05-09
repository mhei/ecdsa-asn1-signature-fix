// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © 2023 Michael Heimpold <mhei@heimpold.de>
 */
#include <stdint.h>
#include <string.h>

int asn1_canonicalize_integer(uint8_t *tag)
{
	uint8_t *length = &tag[1];
	uint8_t *value = &tag[2];
	uint8_t *old_end = value + *length - 1;
	int shift;

	/* safety checks: tag 0x02 = ASN.1 INTEGER and length is short form */
	if (*tag != 0x02 || (*length & 0x80))
		return -1;

	/* determine the shift: check for superfluous leading bytes */
	for (; value < old_end; value++) {
		/* Specification says:
		 * If the contents octets of an integer value encoding consist of more
		 * than one octet, then the bits of the first octet and bit 8 of the
		 * second octet:
		 *   a) shall not all be ones; and
		 *   b) shall not all be zero.
		 */
		switch (*value) {
		case 0x00:
			if ((value[1] & 0x80) == 0)
				continue;
			break;
		case 0xff:
			if ((value[1] & 0x80))
				continue;
			break;
		}

		break;
	}

	/* trim leading superfluous bytes */
	shift = value - &tag[2];
	if (shift) {
		uint8_t *p = &tag[2];
		uint8_t *new_end;

		/* adjust size by subtracting the removed bytes */
		*length -= shift;
		new_end = p + *length;

		for (; p < new_end; p++, value++)
			*p = *value;
	}

	return shift;
}

int asn1_fixup_ecdsa_signature(uint8_t *tag)
{
	uint8_t *seq_length = &tag[1];
	uint8_t *r_tag = &tag[2];
	uint8_t *r_length = &r_tag[1];
	uint8_t *s_tag = r_tag + 2 + *r_length;
	uint8_t *s_length = &s_tag[1];
	int shift = 0;

	/* safety checks: tag 0x30 = ASN.1 SEQUENCE and length is short form */
	if (*tag != 0x30 || (*seq_length & 0x80))
		return -1;

	/* safety checks: check length plausibility */
	if (*r_length + *s_length + 4 != *seq_length)
		return -1;

	/* canonicalize first integer */
	shift += asn1_canonicalize_integer(r_tag);

	/* move the second integer */
	if (shift) {
		memmove(s_tag - shift, s_tag, *s_length + 2);
		s_tag -= shift;
		/* s_length not adjusted since not used below */
	}

	/* canonicalize second integer */
	shift += asn1_canonicalize_integer(s_tag);

	/* adjust sequence length */
	*seq_length -= shift;

	return *seq_length + 2;
}
