/* SPDX-License-Identifier: GPL-2.0-only */
/*
<<<<<<< HEAD
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
=======
 * Copyright (c) 2020 - 2021, The Linux Foundation. All rights reserved.
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
 */

#ifndef _UFSHCD_CRYPTO_QTI_H
#define _UFSHCD_CRYPTO_QTI_H

#include "cqhci-crypto.h"

void cqhci_crypto_qti_enable(struct cqhci_host *host);

void cqhci_crypto_qti_disable(struct cqhci_host *host);

#ifdef CONFIG_BLK_INLINE_ENCRYPTION
int cqhci_crypto_qti_init_crypto(struct cqhci_host *host,
				 const struct keyslot_mgmt_ll_ops *ksm_ops);
#endif

int cqhci_crypto_qti_debug(struct cqhci_host *host);

void cqhci_crypto_qti_set_vops(struct cqhci_host *host);

int cqhci_crypto_qti_resume(struct cqhci_host *host);
int cqhci_crypto_qti_prep_desc(struct cqhci_host *host,
				struct mmc_request *mrq,
				u64 *ice_ctx);

int cqhci_crypto_qti_reset(struct cqhci_host *host);

<<<<<<< HEAD
=======
int cqhci_crypto_qti_recovery_finish(struct cqhci_host *host);

>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
#endif /* _UFSHCD_ICE_QTI_H */
