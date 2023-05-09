// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright © 2023 Michael Heimpold <mhei@heimpold.de>
 */
#pragma once

#include <stdint.h>

/**
 * @brief Canonicalize the ASN.1 integer representation in the buffer
 *
 * Takes a pointer to the start of an ASN.1 integer binary encoding and
 * checks and fixups the representation by removing too long sign extension
 * or removing leading 0x00 bytes. The modification in done in-place
 * which is safe since it can become only smaller.
 *
 * Examples
 *  - Integer = 72:
 *    - 02 01 48 -> already canonicalize
 *    - 02 03 00 00 48 -> canonicalize to 02 01 48
 *  - Integer = -100
 *    - 02 01 9C -> already canonicalize
 *    - 02 02 FF 9C -> canonicalize to 02 01 9C
 *
 * @param[in] tag pointer the ASN.1 tag start
 * @return Returns the applied shift-count in bytes (if any, else zero),
 *         or -1 in case of any error (safety checks failed).
 */
int asn1_canonicalize_integer(uint8_t *tag);

/**
 * @brief Fixup the ASN.1 representation of an ECDSA signature
 *
 * An ECDSA signature is a sequence of two integers. This function
 * canonicalizes both integers and fixups the sequence length field.
 *
 * Example - not real signature - just sample integers:
 * Input:  30 09 02 03 00 00 48 02 02 00 48
 * Result: 30 06 02 01 48 02 01 48
 *
 * @param[in] tag pointer the ASN.1 tag start
 * @return Returns the new length of the whole ASN.1 structure,
 *         or -1 in case of any error (safety checks failed).
 */
int asn1_fixup_ecdsa_signature(uint8_t *tag);
