/**
 ****************************************************************************************
 *
 * @file dp_rx.h
 *
 * Copyright (C) Amlogic 2012-2024
 *
 ****************************************************************************************
 */

#ifndef _COMMON_FW_DP_RX_H_
#define _COMMON_FW_DP_RX_H_

#ifdef __linux__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/* only valid for non-PCIe implementation and MSDU/A-MSDU */
struct aml_rhd_ext {
    uint16_t sn         :12;
    uint16_t reserved   :2;
    uint16_t qos        :1;
    uint16_t pn_present :1;

    uint64_t pn;                /* WAPI uses 64-bit PN, others only use 48-bit */
} __packed;

#endif /* _COMMON_FW_DP_RX_H_ */
