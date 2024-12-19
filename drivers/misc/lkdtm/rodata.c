// SPDX-License-Identifier: GPL-2.0
/*
 * This includes functions that are meant to live entirely in .rodata
 * (via objcopy tricks), to validate the non-executability of .rodata.
 */
#include "lkdtm.h"

<<<<<<< HEAD
void notrace lkdtm_rodata_do_nothing(void)
=======
void noinstr lkdtm_rodata_do_nothing(void)
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
{
	/* Does nothing. We just want an architecture agnostic "return". */
}
