/**
 ******************************************************************************
 *
 * @file rwnx_main.c
 *
 * @brief Entry point of the RWNX driver
 *
 * Copyright (C) RivieraWaves 2012-2021
 *
 ******************************************************************************
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/inetdevice.h>
#include <net/cfg80211.h>
#include <net/ip.h>
#include <linux/etherdevice.h>
#include <net/addrconf.h>

#include "rwnx_defs.h"
#include "rwnx_dini.h"
#include "rwnx_msg_tx.h"
#include "rwnx_tx.h"
#include "reg_access.h"
#include "hal_desc.h"
#include "rwnx_debugfs.h"
#include "rwnx_cfgfile.h"
#include "rwnx_irqs.h"
#include "rwnx_radar.h"
#include "rwnx_version.h"
#ifdef CONFIG_RWNX_BFMER
#include "rwnx_bfmer.h"
#endif //(CONFIG_RWNX_BFMER)
#include "rwnx_tdls.h"
#include "rwnx_events.h"
#include "rwnx_compat.h"
#include "rwnx_iwpriv_cmds.h"
#include "fi_cmd.h"
#include "rwnx_main.h"
#include "rwnx_regdom.h"

#define RW_DRV_DESCRIPTION  "RivieraWaves 11nac driver for Linux cfg80211"
#define RW_DRV_COPYRIGHT    "Copyright (C) RivieraWaves 2015-2021"
#define RW_DRV_AUTHOR       "RivieraWaves S.A.S"

#define PNO_MAX_SUPP_NETWORKS  16


#define RWNX_PRINT_CFM_ERR(req) \
        printk(KERN_CRIT "%s: Status Error(%d)\n", #req, (&req##_cfm)->status)

#define RWNX_HT_CAPABILITIES                                    \
{                                                               \
    .ht_supported   = true,                                     \
    .cap            = 0,                                        \
    .ampdu_factor   = IEEE80211_HT_MAX_AMPDU_64K,               \
    .ampdu_density  = IEEE80211_HT_MPDU_DENSITY_16,             \
    .mcs        = {                                             \
        .rx_mask = { 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, },        \
        .rx_highest = cpu_to_le16(65),                          \
        .tx_params = IEEE80211_HT_MCS_TX_DEFINED,               \
    },                                                          \
}

#define RWNX_VHT_CAPABILITIES                                   \
{                                                               \
    .vht_supported = false,                                     \
    .cap       =                                                \
      (7 << IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_SHIFT),\
    .vht_mcs       = {                                          \
        .rx_mcs_map = cpu_to_le16(                              \
                      IEEE80211_VHT_MCS_SUPPORT_0_9    << 0  |  \
                      IEEE80211_VHT_MCS_NOT_SUPPORTED  << 2  |  \
                      IEEE80211_VHT_MCS_NOT_SUPPORTED  << 4  |  \
                      IEEE80211_VHT_MCS_NOT_SUPPORTED  << 6  |  \
                      IEEE80211_VHT_MCS_NOT_SUPPORTED  << 8  |  \
                      IEEE80211_VHT_MCS_NOT_SUPPORTED  << 10 |  \
                      IEEE80211_VHT_MCS_NOT_SUPPORTED  << 12 |  \
                      IEEE80211_VHT_MCS_NOT_SUPPORTED  << 14),  \
        .tx_mcs_map = cpu_to_le16(                              \
                      IEEE80211_VHT_MCS_SUPPORT_0_9    << 0  |  \
                      IEEE80211_VHT_MCS_NOT_SUPPORTED  << 2  |  \
                      IEEE80211_VHT_MCS_NOT_SUPPORTED  << 4  |  \
                      IEEE80211_VHT_MCS_NOT_SUPPORTED  << 6  |  \
                      IEEE80211_VHT_MCS_NOT_SUPPORTED  << 8  |  \
                      IEEE80211_VHT_MCS_NOT_SUPPORTED  << 10 |  \
                      IEEE80211_VHT_MCS_NOT_SUPPORTED  << 12 |  \
                      IEEE80211_VHT_MCS_NOT_SUPPORTED  << 14),  \
    }                                                           \
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
#define RWNX_HE_CAPABILITIES                                    \
{                                                               \
    .has_he = false,                                            \
    .he_cap_elem = {                                            \
        .mac_cap_info[0] = 0,                                   \
        .mac_cap_info[1] = 0,                                   \
        .mac_cap_info[2] = 0,                                   \
        .mac_cap_info[3] = 0,                                   \
        .mac_cap_info[4] = 0,                                   \
        .mac_cap_info[5] = 0,                                   \
        .phy_cap_info[0] = 0,                                   \
        .phy_cap_info[1] = 0,                                   \
        .phy_cap_info[2] = 0,                                   \
        .phy_cap_info[3] = 0,                                   \
        .phy_cap_info[4] = 0,                                   \
        .phy_cap_info[5] = 0,                                   \
        .phy_cap_info[6] = 0,                                   \
        .phy_cap_info[7] = 0,                                   \
        .phy_cap_info[8] = 0,                                   \
        .phy_cap_info[9] = 0,                                   \
        .phy_cap_info[10] = 0,                                  \
    },                                                          \
    .he_mcs_nss_supp = {                                        \
        .rx_mcs_80 = cpu_to_le16(0xfffa),                       \
        .tx_mcs_80 = cpu_to_le16(0xfffa),                       \
        .rx_mcs_160 = cpu_to_le16(0xffff),                      \
        .tx_mcs_160 = cpu_to_le16(0xffff),                      \
        .rx_mcs_80p80 = cpu_to_le16(0xffff),                    \
        .tx_mcs_80p80 = cpu_to_le16(0xffff),                    \
    },                                                          \
    .ppe_thres = {0x00},                                        \
}
#endif

#define RATE(_bitrate, _hw_rate, _flags) {      \
    .bitrate    = (_bitrate),                   \
    .flags      = (_flags),                     \
    .hw_value   = (_hw_rate),                   \
}

#define CHAN(_freq) {                           \
    .center_freq    = (_freq),                  \
    .max_power  = 30, /* FIXME */               \
}

static struct ieee80211_rate rwnx_ratetable[] = {
    RATE(10,  0x00, 0),
    RATE(20,  0x01, IEEE80211_RATE_SHORT_PREAMBLE),
    RATE(55,  0x02, IEEE80211_RATE_SHORT_PREAMBLE),
    RATE(110, 0x03, IEEE80211_RATE_SHORT_PREAMBLE),
    RATE(60,  0x04, 0),
    RATE(90,  0x05, 0),
    RATE(120, 0x06, 0),
    RATE(180, 0x07, 0),
    RATE(240, 0x08, 0),
    RATE(360, 0x09, 0),
    RATE(480, 0x0A, 0),
    RATE(540, 0x0B, 0),
};

/* The channels indexes here are not used anymore */
static struct ieee80211_channel rwnx_2ghz_channels[] = {
    CHAN(2412),
    CHAN(2417),
    CHAN(2422),
    CHAN(2427),
    CHAN(2432),
    CHAN(2437),
    CHAN(2442),
    CHAN(2447),
    CHAN(2452),
    CHAN(2457),
    CHAN(2462),
    CHAN(2467),
    CHAN(2472),
    CHAN(2484),
    // Extra channels defined only to be used for PHY measures.
    // Enabled only if custregd and custchan parameters are set
    CHAN(2390),
    CHAN(2400),
    CHAN(2410),
    CHAN(2420),
    CHAN(2430),
    CHAN(2440),
    CHAN(2450),
    CHAN(2460),
    CHAN(2470),
    CHAN(2480),
    CHAN(2490),
    CHAN(2500),
    CHAN(2510),
};

static struct ieee80211_channel rwnx_5ghz_channels[] = {
    CHAN(5180),             // 36 -   20MHz
    CHAN(5200),             // 40 -   20MHz
    CHAN(5220),             // 44 -   20MHz
    CHAN(5240),             // 48 -   20MHz
    CHAN(5260),             // 52 -   20MHz
    CHAN(5280),             // 56 -   20MHz
    CHAN(5300),             // 60 -   20MHz
    CHAN(5320),             // 64 -   20MHz
    CHAN(5500),             // 100 -  20MHz
    CHAN(5520),             // 104 -  20MHz
    CHAN(5540),             // 108 -  20MHz
    CHAN(5560),             // 112 -  20MHz
    CHAN(5580),             // 116 -  20MHz
    CHAN(5600),             // 120 -  20MHz
    CHAN(5620),             // 124 -  20MHz
    CHAN(5640),             // 128 -  20MHz
    CHAN(5660),             // 132 -  20MHz
    CHAN(5680),             // 136 -  20MHz
    CHAN(5700),             // 140 -  20MHz
    CHAN(5720),             // 144 -  20MHz
    CHAN(5745),             // 149 -  20MHz
    CHAN(5765),             // 153 -  20MHz
    CHAN(5785),             // 157 -  20MHz
    CHAN(5805),             // 161 -  20MHz
    CHAN(5825),             // 165 -  20MHz
    CHAN(5845),             // 168 -  20MHz
    CHAN(5865),             // 173 -  20MHz
    CHAN(5885),             // 177 -  20MHz
    // Extra channels defined only to be used for PHY measures.
    // Enabled only if custregd and custchan parameters are set
    CHAN(5190),
    CHAN(5210),
    CHAN(5230),
    CHAN(5250),
    CHAN(5270),
    CHAN(5290),
    CHAN(5310),
    CHAN(5330),
    CHAN(5340),
    CHAN(5350),
    CHAN(5360),
    CHAN(5370),
    CHAN(5380),
    CHAN(5390),
    CHAN(5400),
    CHAN(5410),
    CHAN(5420),
    CHAN(5430),
    CHAN(5440),
    CHAN(5450),
    CHAN(5460),
    CHAN(5470),
    CHAN(5480),
    CHAN(5490),
    CHAN(5510),
    CHAN(5530),
    CHAN(5550),
    CHAN(5570),
    CHAN(5590),
    CHAN(5610),
    CHAN(5630),
    CHAN(5650),
    CHAN(5670),
    CHAN(5690),
    CHAN(5710),
    CHAN(5730),
    CHAN(5750),
    CHAN(5760),
    CHAN(5770),
    CHAN(5780),
    CHAN(5790),
    CHAN(5800),
    CHAN(5810),
    CHAN(5820),
    CHAN(5830),
    CHAN(5840),
    CHAN(5850),
    CHAN(5860),
    CHAN(5870),
    CHAN(5880),
    CHAN(5890),
    CHAN(5900),
    CHAN(5910),
    CHAN(5920),
    CHAN(5930),
    CHAN(5940),
    CHAN(5950),
    CHAN(5960),
    CHAN(5970),
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
static struct ieee80211_sband_iftype_data rwnx_he_capa = {
    .types_mask = BIT(NL80211_IFTYPE_STATION) | BIT(NL80211_IFTYPE_AP),
    .he_cap = RWNX_HE_CAPABILITIES,
};
#endif

static struct ieee80211_supported_band rwnx_band_2GHz = {
    .channels   = rwnx_2ghz_channels,
    .n_channels = ARRAY_SIZE(rwnx_2ghz_channels) - 13, // -13 to exclude extra channels
    .bitrates   = rwnx_ratetable,
    .n_bitrates = ARRAY_SIZE(rwnx_ratetable),
    .ht_cap     = RWNX_HT_CAPABILITIES,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
    .iftype_data = &rwnx_he_capa,
    .n_iftype_data = 1,
#endif
};

static struct ieee80211_supported_band rwnx_band_5GHz = {
    .channels   = rwnx_5ghz_channels,
    .n_channels = ARRAY_SIZE(rwnx_5ghz_channels) - 59, // -59 to exclude extra channels
    .bitrates   = &rwnx_ratetable[4],
    .n_bitrates = ARRAY_SIZE(rwnx_ratetable) - 4,
    .ht_cap     = RWNX_HT_CAPABILITIES,
    .vht_cap    = RWNX_VHT_CAPABILITIES,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
    .iftype_data = &rwnx_he_capa,
    .n_iftype_data = 1,
#endif
};

static struct ieee80211_iface_limit rwnx_limits[] = {
    { .max = NX_VIRT_DEV_MAX, .types = BIT(NL80211_IFTYPE_AP) |
                                       BIT(NL80211_IFTYPE_STATION)}
};

static struct ieee80211_iface_limit rwnx_limits_dfs[] = {
    { .max = NX_VIRT_DEV_MAX, .types = BIT(NL80211_IFTYPE_AP)}
};

static const struct ieee80211_iface_combination rwnx_combinations[] = {
    {
        .limits                 = rwnx_limits,
        .n_limits               = ARRAY_SIZE(rwnx_limits),
        .num_different_channels = NX_CHAN_CTXT_CNT,
        .max_interfaces         = NX_VIRT_DEV_MAX,
    },
    /* Keep this combination as the last one */
    {
        .limits                 = rwnx_limits_dfs,
        .n_limits               = ARRAY_SIZE(rwnx_limits_dfs),
        .num_different_channels = 1,
        .max_interfaces         = NX_VIRT_DEV_MAX,
        .radar_detect_widths = (BIT(NL80211_CHAN_WIDTH_20_NOHT) |
                                BIT(NL80211_CHAN_WIDTH_20) |
                                BIT(NL80211_CHAN_WIDTH_40) |
                                BIT(NL80211_CHAN_WIDTH_80)),
    }
};

/* There isn't a lot of sense in it, but you can transmit anything you like */
static struct ieee80211_txrx_stypes
rwnx_default_mgmt_stypes[NUM_NL80211_IFTYPES] = {
    [NL80211_IFTYPE_STATION] = {
        .tx = 0xffff,
        .rx = (BIT(IEEE80211_STYPE_ACTION >> 4) |
               BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
               BIT(IEEE80211_STYPE_AUTH >> 4)),
    },
    [NL80211_IFTYPE_AP] = {
        .tx = 0xffff,
        .rx = (BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
               BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
               BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
               BIT(IEEE80211_STYPE_DISASSOC >> 4) |
               BIT(IEEE80211_STYPE_AUTH >> 4) |
               BIT(IEEE80211_STYPE_DEAUTH >> 4) |
               BIT(IEEE80211_STYPE_ACTION >> 4)),
    },
    [NL80211_IFTYPE_AP_VLAN] = {
        /* copy AP */
        .tx = 0xffff,
        .rx = (BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
               BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
               BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
               BIT(IEEE80211_STYPE_DISASSOC >> 4) |
               BIT(IEEE80211_STYPE_AUTH >> 4) |
               BIT(IEEE80211_STYPE_DEAUTH >> 4) |
               BIT(IEEE80211_STYPE_ACTION >> 4)),
    },
    [NL80211_IFTYPE_P2P_CLIENT] = {
        .tx = 0xffff,
        .rx = (BIT(IEEE80211_STYPE_ACTION >> 4) |
               BIT(IEEE80211_STYPE_PROBE_REQ >> 4)),
    },
    [NL80211_IFTYPE_P2P_GO] = {
        .tx = 0xffff,
        .rx = (BIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
               BIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
               BIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
               BIT(IEEE80211_STYPE_DISASSOC >> 4) |
               BIT(IEEE80211_STYPE_AUTH >> 4) |
               BIT(IEEE80211_STYPE_DEAUTH >> 4) |
               BIT(IEEE80211_STYPE_ACTION >> 4)),
    },
    [NL80211_IFTYPE_P2P_DEVICE] = {
        .tx = 0xffff,
        .rx = (BIT(IEEE80211_STYPE_ACTION >> 4) |
               BIT(IEEE80211_STYPE_PROBE_REQ >> 4)),
    },
    [NL80211_IFTYPE_MESH_POINT] = {
        .tx = 0xffff,
        .rx = (BIT(IEEE80211_STYPE_ACTION >> 4) |
               BIT(IEEE80211_STYPE_AUTH >> 4) |
               BIT(IEEE80211_STYPE_DEAUTH >> 4)),
    },
};

/* if wowlan is not supported, kernel generate a disconnect at each suspend
 * cf: /net/wireless/sysfs.c, so register a stub wowlan.
 * Moreover wowlan has to be enabled via a the nl80211_set_wowlan callback.
 * (from user space, e.g. iw phy0 wowlan enable)
 */
static const struct wiphy_wowlan_support wowlan_stub =
{
    .flags = WIPHY_WOWLAN_ANY,
    .n_patterns = 0,
    .pattern_max_len = 0,
    .pattern_min_len = 0,
    .max_pkt_offset = 0,
};

static u32 cipher_suites[] = {
    WLAN_CIPHER_SUITE_WEP40,
    WLAN_CIPHER_SUITE_WEP104,
    WLAN_CIPHER_SUITE_TKIP,
    WLAN_CIPHER_SUITE_CCMP,
    0, // reserved entries to enable AES-CMAC, GCMP-128/256, CCMP-256, SMS4
    0,
    0,
    0,
    0,
};

#define NB_RESERVED_CIPHER 5;

static const int rwnx_ac2hwq[1][NL80211_NUM_ACS] = {
    {
        [NL80211_TXQ_Q_VO] = RWNX_HWQ_VO,
        [NL80211_TXQ_Q_VI] = RWNX_HWQ_VI,
        [NL80211_TXQ_Q_BE] = RWNX_HWQ_BE,
        [NL80211_TXQ_Q_BK] = RWNX_HWQ_BK
    }
};

const int rwnx_tid2hwq[IEEE80211_NUM_TIDS] = {
    RWNX_HWQ_BE,
    RWNX_HWQ_BK,
    RWNX_HWQ_BK,
    RWNX_HWQ_BE,
    RWNX_HWQ_VI,
    RWNX_HWQ_VI,
    RWNX_HWQ_VO,
    RWNX_HWQ_VO,
    /* TID_8 is used for management frames */
    RWNX_HWQ_VO,
    /* At the moment, all others TID are mapped to BE */
    RWNX_HWQ_BE,
    RWNX_HWQ_BE,
    RWNX_HWQ_BE,
    RWNX_HWQ_BE,
    RWNX_HWQ_BE,
    RWNX_HWQ_BE,
    RWNX_HWQ_BE,
};

static const int rwnx_hwq2uapsd[NL80211_NUM_ACS] = {
    [RWNX_HWQ_VO] = IEEE80211_WMM_IE_STA_QOSINFO_AC_VO,
    [RWNX_HWQ_VI] = IEEE80211_WMM_IE_STA_QOSINFO_AC_VI,
    [RWNX_HWQ_BE] = IEEE80211_WMM_IE_STA_QOSINFO_AC_BE,
    [RWNX_HWQ_BK] = IEEE80211_WMM_IE_STA_QOSINFO_AC_BK,
};

static char * rf_conf_path = WIFI_CONF_PATH;

extern void rwnx_print_version(void);

/*********************************************************************
 * helper
 *********************************************************************/
struct rwnx_sta *rwnx_get_sta(struct rwnx_hw *rwnx_hw, const u8 *mac_addr)
{
    int i;

    for (i = 0; i < NX_REMOTE_STA_MAX; i++) {
        struct rwnx_sta *sta = &rwnx_hw->sta_table[i];
        if (sta->valid && (memcmp(mac_addr, &sta->mac_addr, 6) == 0))
            return sta;
    }

    return NULL;
}

void rwnx_enable_wapi(struct rwnx_hw *rwnx_hw)
{
    cipher_suites[rwnx_hw->wiphy->n_cipher_suites] = WLAN_CIPHER_SUITE_SMS4;
    rwnx_hw->wiphy->n_cipher_suites ++;
    rwnx_hw->wiphy->flags |= WIPHY_FLAG_CONTROL_PORT_PROTOCOL;
}

void rwnx_enable_mfp(struct rwnx_hw *rwnx_hw)
{
    cipher_suites[rwnx_hw->wiphy->n_cipher_suites] = WLAN_CIPHER_SUITE_AES_CMAC;
    rwnx_hw->wiphy->n_cipher_suites ++;
}

void rwnx_enable_gcmp(struct rwnx_hw *rwnx_hw)
{
    // Assume that HW supports CCMP-256 if it supports GCMP
    cipher_suites[rwnx_hw->wiphy->n_cipher_suites++] = WLAN_CIPHER_SUITE_CCMP_256;
    cipher_suites[rwnx_hw->wiphy->n_cipher_suites++] = WLAN_CIPHER_SUITE_GCMP;
    cipher_suites[rwnx_hw->wiphy->n_cipher_suites++] = WLAN_CIPHER_SUITE_GCMP_256;
}

u8 *rwnx_build_bcn(struct rwnx_bcn *bcn, struct cfg80211_beacon_data *new)
{
    u8 *buf, *pos;

    if (new->head) {
        u8 *head = kmalloc(new->head_len, GFP_KERNEL);

        if (!head)
            return NULL;

        if (bcn->head)
            kfree(bcn->head);

        bcn->head = head;
        bcn->head_len = new->head_len;
        memcpy(bcn->head, new->head, new->head_len);
    }
    if (new->tail) {
        u8 *tail = kmalloc(new->tail_len, GFP_KERNEL);

        if (!tail)
            return NULL;

        if (bcn->tail)
            kfree(bcn->tail);

        bcn->tail = tail;
        bcn->tail_len = new->tail_len;
        memcpy(bcn->tail, new->tail, new->tail_len);
    }

    if (!bcn->head)
        return NULL;

    bcn->tim_len = 6;
    bcn->len = bcn->head_len + bcn->tail_len + bcn->ies_len + bcn->tim_len;

    buf = kmalloc(bcn->len, GFP_KERNEL);
    if (!buf)
        return NULL;

    // Build the beacon buffer
    pos = buf;
    memcpy(pos, bcn->head, bcn->head_len);
    pos += bcn->head_len;
    *pos++ = WLAN_EID_TIM;
    *pos++ = 4;
    *pos++ = 0;
    *pos++ = bcn->dtim;
    *pos++ = 0;
    *pos++ = 0;
    if (bcn->tail) {
        memcpy(pos, bcn->tail, bcn->tail_len);
        pos += bcn->tail_len;
    }
    if (bcn->ies) {
        memcpy(pos, bcn->ies, bcn->ies_len);
    }

    return buf;
}

static void rwnx_del_bcn(struct rwnx_bcn *bcn)
{
    if (bcn->head) {
        kfree(bcn->head);
        bcn->head = NULL;
    }
    bcn->head_len = 0;

    if (bcn->tail) {
        kfree(bcn->tail);
        bcn->tail = NULL;
    }
    bcn->tail_len = 0;

    if (bcn->ies) {
        kfree(bcn->ies);
        bcn->ies = NULL;
    }
    bcn->ies_len = 0;
    bcn->tim_len = 0;
    bcn->dtim = 0;
    bcn->len = 0;
}

/**
 * Link channel ctxt to a vif and thus increments count for this context.
 */
void rwnx_chanctx_link(struct rwnx_vif *vif, u8 ch_idx,
                       struct cfg80211_chan_def *chandef)
{
    struct rwnx_chanctx *ctxt;

    if (ch_idx >= NX_CHAN_CTXT_CNT) {
        WARN(1, "Invalid channel ctxt id %d", ch_idx);
        return;
    }

    vif->ch_index = ch_idx;
    ctxt = &vif->rwnx_hw->chanctx_table[ch_idx];
    ctxt->count++;

    // For now chandef is NULL for STATION interface
    if (chandef) {
        if (!ctxt->chan_def.chan)
            ctxt->chan_def = *chandef;
        else {
            // TODO. check that chandef is the same as the one already
            // set for this ctxt
        }
    }
}

/**
 * Unlink channel ctxt from a vif and thus decrements count for this context
 */
void rwnx_chanctx_unlink(struct rwnx_vif *vif)
{
    struct rwnx_chanctx *ctxt;

    if (vif->ch_index == RWNX_CH_NOT_SET)
        return;

    ctxt = &vif->rwnx_hw->chanctx_table[vif->ch_index];

    if (ctxt->count == 0) {
        WARN(1, "Chan ctxt ref count is already 0");
    } else {
        ctxt->count--;
    }

    if (ctxt->count == 0) {
        if (vif->ch_index == vif->rwnx_hw->cur_chanctx) {
            /* If current chan ctxt is no longer linked to a vif
               disable radar detection (no need to check if it was activated) */
            rwnx_radar_detection_enable(&vif->rwnx_hw->radar,
                                        RWNX_RADAR_DETECT_DISABLE,
                                        RWNX_RADAR_RIU);
        }
        /* set chan to null, so that if this ctxt is relinked to a vif that
           don't have channel information, don't use wrong information */
        ctxt->chan_def.chan = NULL;
    }
    vif->ch_index = RWNX_CH_NOT_SET;
}

int rwnx_chanctx_valid(struct rwnx_hw *rwnx_hw, u8 ch_idx)
{
    if (ch_idx >= NX_CHAN_CTXT_CNT ||
        rwnx_hw->chanctx_table[ch_idx].chan_def.chan == NULL) {
        return 0;
    }

    return 1;
}

static void rwnx_del_csa(struct rwnx_vif *vif)
{
    struct rwnx_hw *rwnx_hw = vif->rwnx_hw;
    struct rwnx_csa *csa = vif->ap.csa;

    if (!csa)
        return;

    rwnx_ipc_buf_dealloc(rwnx_hw, &csa->buf);
    rwnx_del_bcn(&csa->bcn);
    kfree(csa);
    vif->ap.csa = NULL;
}

static void rwnx_csa_finish(struct work_struct *ws)
{
    struct rwnx_csa *csa = container_of(ws, struct rwnx_csa, work);
    struct rwnx_vif *vif = csa->vif;
    struct rwnx_hw *rwnx_hw = vif->rwnx_hw;
    int error = csa->status;

    if (!error)
        error = rwnx_send_bcn_change(rwnx_hw, vif->vif_index, csa->buf.dma_addr,
                                     csa->bcn.len, csa->bcn.head_len,
                                     csa->bcn.tim_len, NULL);

    if (error)
        cfg80211_stop_iface(rwnx_hw->wiphy, &vif->wdev, GFP_KERNEL);
    else {
        mutex_lock(&vif->wdev.mtx);
        __acquire(&vif->wdev.mtx);
        spin_lock_bh(&rwnx_hw->cb_lock);
        rwnx_chanctx_unlink(vif);
        rwnx_chanctx_link(vif, csa->ch_idx, &csa->chandef);
        if (rwnx_hw->cur_chanctx == csa->ch_idx) {
            rwnx_radar_detection_enable_on_cur_channel(rwnx_hw);
            rwnx_txq_vif_start(vif, RWNX_TXQ_STOP_CHAN, rwnx_hw);
        } else
            rwnx_txq_vif_stop(vif, RWNX_TXQ_STOP_CHAN, rwnx_hw);
        spin_unlock_bh(&rwnx_hw->cb_lock);
        cfg80211_ch_switch_notify(vif->ndev, &csa->chandef);
        mutex_unlock(&vif->wdev.mtx);
        __release(&vif->wdev.mtx);
    }
    rwnx_del_csa(vif);
}

/**
 * rwnx_external_auth_enable - Enable external authentication on a vif
 *
 * @vif: VIF on which external authentication must be enabled
 *
 * External authentication requires to start TXQ for unknown STA in
 * order to send auth frame pusehd by user space.
 * Note: It is assumed that fw is on the correct channel.
 */
void rwnx_external_auth_enable(struct rwnx_vif *vif)
{
    vif->sta.flags |= RWNX_STA_EXT_AUTH;
    rwnx_txq_unk_vif_init(vif);
    rwnx_txq_start(rwnx_txq_vif_get(vif, NX_UNK_TXQ_TYPE), 0);
}

/**
 * rwnx_external_auth_disable - Disable external authentication on a vif
 *
 * @vif: VIF on which external authentication must be disabled
 */
void rwnx_external_auth_disable(struct rwnx_vif *vif)
{
    if (!(vif->sta.flags & RWNX_STA_EXT_AUTH))
        return;

    vif->sta.flags &= ~RWNX_STA_EXT_AUTH;
    rwnx_txq_unk_vif_deinit(vif);
}

/**
 * rwnx_update_mesh_power_mode -
 *
 * @vif: mesh VIF  for which power mode is updated
 *
 * Does nothing if vif is not a mesh point interface.
 * Since firmware doesn't support one power save mode per link select the
 * most "active" power mode among all mesh links.
 * Indeed as soon as we have to be active on one link we might as well be
 * active on all links.
 *
 * If there is no link then the power mode for next peer is used;
 */
void rwnx_update_mesh_power_mode(struct rwnx_vif *vif)
{
    enum nl80211_mesh_power_mode mesh_pm;
    struct rwnx_sta *sta;
    struct mesh_config mesh_conf;
    struct mesh_update_cfm cfm;
    u32 mask;

    memset(&mesh_conf, 0, sizeof(mesh_conf));
    if (RWNX_VIF_TYPE(vif) != NL80211_IFTYPE_MESH_POINT)
        return;

    if (list_empty(&vif->ap.sta_list)) {
        mesh_pm = vif->ap.next_mesh_pm;
    } else {
        mesh_pm = NL80211_MESH_POWER_DEEP_SLEEP;
        list_for_each_entry(sta, &vif->ap.sta_list, list) {
            if (sta->valid && (sta->mesh_pm < mesh_pm)) {
                mesh_pm = sta->mesh_pm;
            }
        }
    }

    if (mesh_pm == vif->ap.mesh_pm)
        return;

    mask = BIT(NL80211_MESHCONF_POWER_MODE - 1);
    mesh_conf.power_mode = mesh_pm;
    if (rwnx_send_mesh_update_req(vif->rwnx_hw, vif, mask, &mesh_conf, &cfm) ||
        cfm.status)
        return;

    vif->ap.mesh_pm = mesh_pm;
}

/**
 * rwnx_save_assoc_ie_for_ft - Save association request elements if Fast
 * Transition has been configured.
 *
 * @vif: VIF that just connected
 * @sme: Connection info
 */
void rwnx_save_assoc_info_for_ft(struct rwnx_vif *vif,
                                 struct cfg80211_connect_params *sme)
{
    int ies_len = sme->ie_len + sme->ssid_len + 2;
    u8 *pos;

    if (!vif->sta.ft_assoc_ies) {
        if (!cfg80211_find_ie(WLAN_EID_MOBILITY_DOMAIN, sme->ie, sme->ie_len))
            return;

        vif->sta.ft_assoc_ies_len = ies_len;
        vif->sta.ft_assoc_ies = kmalloc(ies_len, GFP_KERNEL);
    } else if (vif->sta.ft_assoc_ies_len < ies_len) {
        kfree(vif->sta.ft_assoc_ies);
        vif->sta.ft_assoc_ies = kmalloc(ies_len, GFP_KERNEL);
    }

    if (!vif->sta.ft_assoc_ies)
        return;

    // Also save SSID (as an element) in the buffer
    pos = vif->sta.ft_assoc_ies;
    *pos++ = WLAN_EID_SSID;
    *pos++ = sme->ssid_len;
    memcpy(pos, sme->ssid, sme->ssid_len);
    pos += sme->ssid_len;
    memcpy(pos, sme->ie, sme->ie_len);
    vif->sta.ft_assoc_ies_len = ies_len;
}

/**
 * rwnx_rsne_to_connect_params - Initialise cfg80211_connect_params from
 * RSN element.
 *
 * @rsne: RSN element
 * @sme: Structure cfg80211_connect_params to initialize
 *
 * The goal is only to initialize enough for rwnx_send_sm_connect_req
 */
int rwnx_rsne_to_connect_params(const struct element *rsne,
                                struct cfg80211_connect_params *sme)
{
    int len = rsne->datalen;
    int clen;
    const u8 *pos = rsne->data ;

    if (len < 8)
        return 1;

    sme->crypto.control_port_no_encrypt = false;
    sme->crypto.control_port = true;
    sme->crypto.control_port_ethertype = cpu_to_be16(ETH_P_PAE);

    pos += 2;
    sme->crypto.cipher_group = ntohl(*((u32 *)pos));
    pos += 4;
    clen = le16_to_cpu(*((u16 *)pos)) * 4;
    pos += 2;
    len -= 8;
    if (len < clen + 2)
        return 1;
    // only need one cipher suite
    sme->crypto.n_ciphers_pairwise = 1;
    sme->crypto.ciphers_pairwise[0] = ntohl(*((u32 *)pos));
    pos += clen;
    len -= clen;

    // no need for AKM
    clen = le16_to_cpu(*((u16 *)pos)) * 4;
    pos += 2;
    len -= 2;
    if (len < clen)
        return 1;
    pos += clen;
    len -= clen;

    if (len < 4)
        return 0;

    pos += 2;
    clen = le16_to_cpu(*((u16 *)pos)) * 16;
    len -= 4;
    if (len > clen)
        sme->mfp = NL80211_MFP_REQUIRED;

    return 0;
}

/*********************************************************************
 * netdev callbacks
 ********************************************************************/
/**
 * int (*ndo_open)(struct net_device *dev);
 *     This function is called when network device transistions to the up
 *     state.
 *
 * - Start FW if this is the first interface opened
 * - Add interface at fw level
 */
static int rwnx_open(struct net_device *dev)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct rwnx_hw *rwnx_hw = rwnx_vif->rwnx_hw;
    struct mm_add_if_cfm add_if_cfm;
    int error = 0;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    // Check if it is the first opened VIF
    if (rwnx_hw->vif_started == 0)
    {
        // Start the FW
       if ((error = rwnx_send_start(rwnx_hw)))
           return error;

       /* Device is now started */
       set_bit(RWNX_DEV_STARTED, &rwnx_hw->flags);
    }

    if (RWNX_VIF_TYPE(rwnx_vif) == NL80211_IFTYPE_AP_VLAN) {
        /* For AP_vlan use same fw and drv indexes. We ensure that this index
           will not be used by fw for another vif by taking index >= NX_VIRT_DEV_MAX */
        add_if_cfm.inst_nbr = rwnx_vif->drv_vif_index;
        netif_tx_stop_all_queues(dev);
    } else {
        /* Forward the information to the LMAC,
         *     p2p value not used in FMAC configuration, iftype is sufficient */
        if ((error = rwnx_send_add_if(rwnx_hw, dev->dev_addr,
                                      RWNX_VIF_TYPE(rwnx_vif), false, &add_if_cfm)))
            return error;

        if (add_if_cfm.status != 0) {
            RWNX_PRINT_CFM_ERR(add_if);
            return -EIO;
        }
    }

    /* Save the index retrieved from LMAC */
    spin_lock_bh(&rwnx_hw->cb_lock);
    rwnx_vif->vif_index = add_if_cfm.inst_nbr;
    rwnx_vif->up = true;
    rwnx_hw->vif_started++;
    rwnx_hw->vif_table[add_if_cfm.inst_nbr] = rwnx_vif;
    spin_unlock_bh(&rwnx_hw->cb_lock);

    if (RWNX_VIF_TYPE(rwnx_vif) == NL80211_IFTYPE_MONITOR) {
        rwnx_hw->monitor_vif = rwnx_vif->vif_index;
        if (rwnx_vif->ch_index != RWNX_CH_NOT_SET) {
            //Configure the monitor channel
            error = rwnx_send_config_monitor_req(rwnx_hw,
                                                 &rwnx_hw->chanctx_table[rwnx_vif->ch_index].chan_def,
                                                 NULL);
        }
    }

    netif_carrier_off(dev);

    return error;
}

/**
 * int (*ndo_stop)(struct net_device *dev);
 *     This function is called when network device transistions to the down
 *     state.
 *
 * - Remove interface at fw level
 * - Reset FW if this is the last interface opened
 */
static int rwnx_close(struct net_device *dev)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct rwnx_hw *rwnx_hw = rwnx_vif->rwnx_hw;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    netdev_info(dev, "CLOSE");

    rwnx_radar_cancel_cac(&rwnx_hw->radar);

    /* Abort scan request on the vif */
    if (rwnx_hw->scan_request &&
        rwnx_hw->scan_request->wdev == &rwnx_vif->wdev) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
        struct cfg80211_scan_info info = {
            .aborted = true,
        };

        cfg80211_scan_done(rwnx_hw->scan_request, &info);
#else
        cfg80211_scan_done(rwnx_hw->scan_request, true);
#endif
        rwnx_hw->scan_request = NULL;
    }

    rwnx_send_remove_if(rwnx_hw, rwnx_vif->vif_index);

    if (rwnx_hw->roc && (rwnx_hw->roc->vif == rwnx_vif)) {
        kfree(rwnx_hw->roc);
        rwnx_hw->roc = NULL;
    }

    /* Ensure that we won't process disconnect ind */
    spin_lock_bh(&rwnx_hw->cb_lock);

    rwnx_vif->up = false;
    if (netif_carrier_ok(dev)) {
        if (RWNX_VIF_TYPE(rwnx_vif) == NL80211_IFTYPE_STATION ||
            RWNX_VIF_TYPE(rwnx_vif) == NL80211_IFTYPE_P2P_CLIENT) {
            if (rwnx_vif->sta.ft_assoc_ies) {
                kfree(rwnx_vif->sta.ft_assoc_ies);
                rwnx_vif->sta.ft_assoc_ies = NULL;
                rwnx_vif->sta.ft_assoc_ies_len = 0;
            }
            cfg80211_disconnected(dev, WLAN_REASON_DEAUTH_LEAVING,
                                  NULL, 0, true, GFP_ATOMIC);
            if (rwnx_vif->sta.ap) {
                rwnx_txq_sta_deinit(rwnx_hw, rwnx_vif->sta.ap);
                rwnx_txq_tdls_vif_deinit(rwnx_vif);
            }
            netif_tx_stop_all_queues(dev);
            netif_carrier_off(dev);
        } else if (RWNX_VIF_TYPE(rwnx_vif) == NL80211_IFTYPE_AP_VLAN) {
            netif_carrier_off(dev);
        } else {
            netdev_warn(dev, "AP not stopped when disabling interface");
        }
    }

    rwnx_hw->vif_table[rwnx_vif->vif_index] = NULL;
    spin_unlock_bh(&rwnx_hw->cb_lock);

    rwnx_chanctx_unlink(rwnx_vif);

    if (RWNX_VIF_TYPE(rwnx_vif) == NL80211_IFTYPE_MONITOR)
        rwnx_hw->monitor_vif = RWNX_INVALID_VIF;

    rwnx_hw->vif_started--;
    if (rwnx_hw->vif_started == 0) {
        /* This also lets both ipc sides remain in sync before resetting */
        rwnx_ipc_tx_drain(rwnx_hw);

        rwnx_send_reset(rwnx_hw);

        // Set parameters to firmware
        rwnx_send_me_config_req(rwnx_hw);

        // Set channel parameters to firmware
        rwnx_send_me_chan_config_req(rwnx_hw);

        clear_bit(RWNX_DEV_STARTED, &rwnx_hw->flags);
    }

    return 0;
}

/**
 * struct net_device_stats* (*ndo_get_stats)(struct net_device *dev);
 *	Called when a user wants to get the network device usage
 *	statistics. Drivers must do one of the following:
 *	1. Define @ndo_get_stats64 to fill in a zero-initialised
 *	   rtnl_link_stats64 structure passed by the caller.
 *	2. Define @ndo_get_stats to update a net_device_stats structure
 *	   (which should normally be dev->stats) and return a pointer to
 *	   it. The structure may be changed asynchronously only if each
 *	   field is written atomically.
 *	3. Update dev->stats asynchronously and atomically, and define
 *	   neither operation.
 */
static struct net_device_stats *rwnx_get_stats(struct net_device *dev)
{
    struct rwnx_vif *vif = netdev_priv(dev);

    return &vif->net_stats;
}

/**
 * u16 (*ndo_select_queue)(struct net_device *dev, struct sk_buff *skb,
 *                         struct net_device *sb_dev);
 *	Called to decide which queue to when device supports multiple
 *	transmit queues.
 */
u16 rwnx_select_queue(struct net_device *dev, struct sk_buff *skb,
                      struct net_device *sb_dev)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    return rwnx_select_txq(rwnx_vif, skb);
}

/**
 * int (*ndo_set_mac_address)(struct net_device *dev, void *addr);
 *	This function  is called when the Media Access Control address
 *	needs to be changed. If this interface is not defined, the
 *	mac address can not be changed.
 */
static int rwnx_set_mac_address(struct net_device *dev, void *addr)
{
    struct sockaddr *sa = addr;
    int ret;

    ret = eth_mac_addr(dev, sa);

    return ret;
}

static int rwnx_priv_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
    //struct rwnx_vif *rwnx_vif = netdev_priv(dev);

    /* FIXME: android will call SIOCDEVPRIVATE+1, if invokes failed,
     * it will cause the dynamic p2p interface create failed. */
    switch (cmd) {
        case SIOCDEVPRIVATE + 1:
            return 0;
        default:
            break;
    }
    return -EINVAL;
}

static const struct net_device_ops rwnx_netdev_ops = {
    .ndo_open               = rwnx_open,
    .ndo_stop               = rwnx_close,
    .ndo_start_xmit         = rwnx_start_xmit,
    .ndo_get_stats          = rwnx_get_stats,
    .ndo_select_queue       = rwnx_select_queue,
    .ndo_set_mac_address    = rwnx_set_mac_address,
    .ndo_do_ioctl           = rwnx_priv_ioctl,
//    .ndo_set_features       = rwnx_set_features,
//    .ndo_set_rx_mode        = rwnx_set_multicast_list,
};

static const struct net_device_ops rwnx_netdev_monitor_ops = {
    .ndo_open               = rwnx_open,
    .ndo_stop               = rwnx_close,
    .ndo_get_stats          = rwnx_get_stats,
    .ndo_set_mac_address    = rwnx_set_mac_address,
};

static void rwnx_netdev_setup(struct net_device *dev)
{
    ether_setup(dev);
    dev->priv_flags &= ~IFF_TX_SKB_SHARING;
    dev->netdev_ops = &rwnx_netdev_ops;
#if LINUX_VERSION_CODE <  KERNEL_VERSION(4, 12, 0)
    dev->destructor = free_netdev;
#else
    dev->needs_free_netdev = true;
#endif
    dev->watchdog_timeo = RWNX_TX_LIFETIME_MS;

    dev->needed_headroom = RWNX_TX_MAX_HEADROOM;
#ifdef CONFIG_RWNX_AMSDUS_TX
    dev->needed_headroom = max(dev->needed_headroom,
                               (unsigned short)(sizeof(struct rwnx_amsdu_txhdr)
                                                + sizeof(struct ethhdr) + 4
                                                + sizeof(rfc1042_header) + 2));
#endif /* CONFIG_RWNX_AMSDUS_TX */

    //add iwpriv_cmd module
    dev->wireless_handlers = &iw_handle;

    dev->hw_features = 0;
}

/*********************************************************************
 * Cfg80211 callbacks (and helper)
 *********************************************************************/
static struct wireless_dev *rwnx_interface_add(struct rwnx_hw *rwnx_hw,
                                               const char *name,
                                               unsigned char name_assign_type,
                                               enum nl80211_iftype type,
                                               struct vif_params *params)
{
    struct net_device *ndev;
    struct rwnx_vif *vif;
    int min_idx, max_idx;
    int vif_idx = -1;
    int i;

    RWNX_INFO("interface type=%d\n", type);
    // Look for an available VIF
    if (type == NL80211_IFTYPE_AP_VLAN) {
        min_idx = NX_VIRT_DEV_MAX;
        max_idx = NX_ITF_MAX;
    } else {
        min_idx = 0;
        max_idx = NX_VIRT_DEV_MAX;
    }

    for (i = min_idx; i < max_idx; i++) {
        if ((rwnx_hw->avail_idx_map) & BIT(i)) {
            vif_idx = i;
            break;
        }
    }
    if (vif_idx < 0)
        return NULL;

    #ifndef CONFIG_RWNX_MON_DATA
    list_for_each_entry(vif, &rwnx_hw->vifs, list) {
        // Check if monitor interface already exists or type is monitor
        if ((RWNX_VIF_TYPE(vif) == NL80211_IFTYPE_MONITOR) ||
           (type == NL80211_IFTYPE_MONITOR)) {
            wiphy_err(rwnx_hw->wiphy,
                    "Monitor+Data interface support (MON_DATA) disabled\n");
            return NULL;
        }
    }
    #endif

    ndev = alloc_netdev_mqs(sizeof(*vif), name, name_assign_type,
                            rwnx_netdev_setup, NX_NB_NDEV_TXQ, 1);
    if (!ndev)
        return NULL;

    vif = netdev_priv(ndev);
    ndev->ieee80211_ptr = &vif->wdev;
    vif->wdev.wiphy = rwnx_hw->wiphy;
    vif->rwnx_hw = rwnx_hw;
    vif->ndev = ndev;
    vif->drv_vif_index = vif_idx;
    SET_NETDEV_DEV(ndev, wiphy_dev(vif->wdev.wiphy));
    vif->wdev.netdev = ndev;
    vif->wdev.iftype = type;
    vif->up = false;
    vif->ch_index = RWNX_CH_NOT_SET;
    vif->generation = 0;
    memset(&vif->net_stats, 0, sizeof(vif->net_stats));

    switch (type) {
    case NL80211_IFTYPE_STATION:
    case NL80211_IFTYPE_P2P_CLIENT:
    case NL80211_IFTYPE_P2P_DEVICE:
        vif->sta.flags = 0;
        vif->sta.ap = NULL;
        vif->sta.tdls_sta = NULL;
        vif->sta.ft_assoc_ies = NULL;
        vif->sta.ft_assoc_ies_len = 0;
        vif->sta.scan_hang = 0;
        vif->sta.scan_duration = 0;
        vif->sta.cancel_scan_cfm = 0;
        break;
    case NL80211_IFTYPE_MESH_POINT:
        INIT_LIST_HEAD(&vif->ap.mpath_list);
        INIT_LIST_HEAD(&vif->ap.proxy_list);
        vif->ap.mesh_pm = NL80211_MESH_POWER_ACTIVE;
        vif->ap.next_mesh_pm = NL80211_MESH_POWER_ACTIVE;
        // no break
    case NL80211_IFTYPE_AP:
    case NL80211_IFTYPE_P2P_GO:
        INIT_LIST_HEAD(&vif->ap.sta_list);
        memset(&vif->ap.bcn, 0, sizeof(vif->ap.bcn));
        vif->ap.flags = 0;
        break;
    case NL80211_IFTYPE_AP_VLAN:
    {
        struct rwnx_vif *master_vif;
        bool found = false;
        list_for_each_entry(master_vif, &rwnx_hw->vifs, list) {
            if ((RWNX_VIF_TYPE(master_vif) == NL80211_IFTYPE_AP) &&
                !(!memcmp(master_vif->ndev->dev_addr, params->macaddr,
                           ETH_ALEN))) {
                 found=true;
                 break;
            }
        }

        if (!found)
            goto err;

         vif->ap_vlan.master = master_vif;
         vif->ap_vlan.sta_4a = NULL;
         break;
    }
    case NL80211_IFTYPE_MONITOR:
        ndev->type = ARPHRD_IEEE80211_RADIOTAP;
        ndev->netdev_ops = &rwnx_netdev_monitor_ops;
        break;
    default:
        break;
    }

    if (type == NL80211_IFTYPE_AP_VLAN)
        memcpy(ndev->dev_addr, params->macaddr, ETH_ALEN);
    else {
        memcpy(ndev->dev_addr, rwnx_hw->wiphy->perm_addr, ETH_ALEN);
        ndev->dev_addr[5] ^= vif_idx;
    }

    if (params) {
        vif->use_4addr = params->use_4addr;
        ndev->ieee80211_ptr->use_4addr = params->use_4addr;
    } else
        vif->use_4addr = false;


    if (register_netdevice(ndev))
        goto err;

    spin_lock_bh(&rwnx_hw->cb_lock);
    list_add_tail(&vif->list, &rwnx_hw->vifs);
    spin_unlock_bh(&rwnx_hw->cb_lock);
    rwnx_hw->avail_idx_map &= ~BIT(vif_idx);

    return &vif->wdev;

err:
    free_netdev(ndev);
    return NULL;
}

/**
 * @brief Retrieve the rwnx_sta object allocated for a given MAC address
 * and a given role.
 */
static struct rwnx_sta *rwnx_retrieve_sta(struct rwnx_hw *rwnx_hw,
                                          struct rwnx_vif *rwnx_vif, u8 *addr,
                                          __le16 fc, bool ap)
{
    if (ap) {
        /* only deauth, disassoc and action are bufferable MMPDUs */
        bool bufferable = ieee80211_is_deauth(fc) ||
                          ieee80211_is_disassoc(fc) ||
                          ieee80211_is_action(fc);

        /* Check if the packet is bufferable or not */
        if (bufferable)
        {
            /* Check if address is a broadcast or a multicast address */
            if (is_broadcast_ether_addr(addr) || is_multicast_ether_addr(addr)) {
                /* Returned STA pointer */
                struct rwnx_sta *rwnx_sta = &rwnx_hw->sta_table[rwnx_vif->ap.bcmc_index];

                if (rwnx_sta->valid)
                    return rwnx_sta;
            } else {
                /* Returned STA pointer */
                struct rwnx_sta *rwnx_sta;

                /* Go through list of STAs linked with the provided VIF */
                list_for_each_entry(rwnx_sta, &rwnx_vif->ap.sta_list, list) {
                    if (rwnx_sta->valid &&
                        ether_addr_equal(rwnx_sta->mac_addr, addr)) {
                        /* Return the found STA */
                        return rwnx_sta;
                    }
                }
            }
        }
    } else {
        return rwnx_vif->sta.ap;
    }

    return NULL;
}

/**
 * @add_virtual_intf: create a new virtual interface with the given name,
 *	must set the struct wireless_dev's iftype. Beware: You must create
 *	the new netdev in the wiphy's network namespace! Returns the struct
 *	wireless_dev, or an ERR_PTR. For P2P device wdevs, the driver must
 *	also set the address member in the wdev.
 */
static struct wireless_dev *rwnx_cfg80211_add_iface(struct wiphy *wiphy,
                                                    const char *name,
                                                    unsigned char name_assign_type,
                                                    enum nl80211_iftype type,
                                                    struct vif_params *params)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct wireless_dev *wdev;

    wdev = rwnx_interface_add(rwnx_hw, name, name_assign_type, type, params);

    if (!wdev)
        return ERR_PTR(-EINVAL);

    return wdev;
}

/**
 * @del_virtual_intf: remove the virtual interface
 */
static int rwnx_cfg80211_del_iface(struct wiphy *wiphy, struct wireless_dev *wdev)
{
    struct net_device *dev = wdev->netdev;
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);

    netdev_info(dev, "Remove Interface");

    if (dev->reg_state == NETREG_REGISTERED) {
        /* Will call rwnx_close if interface is UP */
        unregister_netdevice(dev);
    }

    spin_lock_bh(&rwnx_hw->cb_lock);
    list_del(&rwnx_vif->list);
    spin_unlock_bh(&rwnx_hw->cb_lock);
    rwnx_hw->avail_idx_map |= BIT(rwnx_vif->drv_vif_index);
    rwnx_vif->ndev = NULL;

    /* Clear the priv in adapter */
    dev->ieee80211_ptr = NULL;

    return 0;
}

/**
 * @change_virtual_intf: change type/configuration of virtual interface,
 *	keep the struct wireless_dev's iftype updated.
 */
int rwnx_cfg80211_change_iface(struct wiphy *wiphy,
                                      struct net_device *dev,
                                      enum nl80211_iftype type,
                                      struct vif_params *params)
{
#ifndef CONFIG_RWNX_MON_DATA
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
#endif
    struct rwnx_vif *vif = netdev_priv(dev);

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    RWNX_INFO("interface type=%d\n", type);
    if (vif->up)
        return (-EBUSY);

#ifndef CONFIG_RWNX_MON_DATA
    if ((type == NL80211_IFTYPE_MONITOR) &&
       (RWNX_VIF_TYPE(vif) != NL80211_IFTYPE_MONITOR)) {
        struct rwnx_vif *vif_el;
        list_for_each_entry(vif_el, &rwnx_hw->vifs, list) {
            // Check if data interface already exists
            if ((vif_el != vif) &&
               (RWNX_VIF_TYPE(vif) != NL80211_IFTYPE_MONITOR)) {
                wiphy_err(rwnx_hw->wiphy,
                        "Monitor+Data interface support (MON_DATA) disabled\n");
                return -EIO;
            }
        }
    }
#endif

    // Reset to default case (i.e. not monitor)
    dev->type = ARPHRD_ETHER;
    dev->netdev_ops = &rwnx_netdev_ops;

    switch (type) {
    case NL80211_IFTYPE_STATION:
    case NL80211_IFTYPE_P2P_CLIENT:
    case NL80211_IFTYPE_P2P_DEVICE:
        vif->sta.flags = 0;
        vif->sta.ap = NULL;
        vif->sta.tdls_sta = NULL;
        vif->sta.ft_assoc_ies = NULL;
        vif->sta.ft_assoc_ies_len = 0;
        break;
    case NL80211_IFTYPE_MESH_POINT:
        INIT_LIST_HEAD(&vif->ap.mpath_list);
        INIT_LIST_HEAD(&vif->ap.proxy_list);
        // no break
    case NL80211_IFTYPE_AP:
    case NL80211_IFTYPE_P2P_GO:
        INIT_LIST_HEAD(&vif->ap.sta_list);
        memset(&vif->ap.bcn, 0, sizeof(vif->ap.bcn));
        vif->ap.flags = 0;
        break;
    case NL80211_IFTYPE_AP_VLAN:
        return -EPERM;
    case NL80211_IFTYPE_MONITOR:
        dev->type = ARPHRD_IEEE80211_RADIOTAP;
        dev->netdev_ops = &rwnx_netdev_monitor_ops;
        break;
    default:
        break;
    }

    vif->generation = 0;
    vif->wdev.iftype = type;
    if (params && params->use_4addr != -1)
        vif->use_4addr = params->use_4addr;

    return 0;
}

/**
 * @scan: Request to do a scan. If returning zero, the scan request is given
 *	the driver, and will be valid until passed to cfg80211_scan_done().
 *	For scan results, call cfg80211_inform_bss(); you can call this outside
 *	the scan/scan_done bracket too.
 */
static int rwnx_cfg80211_scan(struct wiphy *wiphy,
                              struct cfg80211_scan_request *request)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = container_of(request->wdev, struct rwnx_vif,
                                             wdev);
    int error;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    if (rwnx_vif->sta.scan_hang) {
        printk("%s scan_hang is on ,can't scan now!\n", __func__);
        return -EAGAIN;
    }

    if ((error = rwnx_send_scanu_req(rwnx_hw, rwnx_vif, request)))
        return error;

    rwnx_hw->scan_request = request;

    return 0;
}

/**
 * @add_key: add a key with the given parameters. @mac_addr will be %NULL
 *	when adding a group key.
 */
static int rwnx_cfg80211_add_key(struct wiphy *wiphy, struct net_device *netdev,
                                 u8 key_index, bool pairwise, const u8 *mac_addr,
                                 struct key_params *params)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *vif = netdev_priv(netdev);
    int i, error = 0;
    struct mm_key_add_cfm key_add_cfm;
    u8_l cipher = 0;
    struct rwnx_sta *sta = NULL;
    struct rwnx_key *rwnx_key;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    if (mac_addr) {
        sta = rwnx_get_sta(rwnx_hw, mac_addr);
        if (!sta)
            return -EINVAL;
        rwnx_key = &sta->key;
    }
    else
        rwnx_key = &vif->key[key_index];

    /* Retrieve the cipher suite selector */
    switch (params->cipher) {
    case WLAN_CIPHER_SUITE_WEP40:
        cipher = MAC_CIPHER_WEP40;
        break;
    case WLAN_CIPHER_SUITE_WEP104:
        cipher = MAC_CIPHER_WEP104;
        break;
    case WLAN_CIPHER_SUITE_TKIP:
        cipher = MAC_CIPHER_TKIP;
        break;
    case WLAN_CIPHER_SUITE_CCMP:
        cipher = MAC_CIPHER_CCMP;
        break;
    case WLAN_CIPHER_SUITE_AES_CMAC:
        cipher = MAC_CIPHER_BIP_CMAC_128;
        break;
    case WLAN_CIPHER_SUITE_SMS4:
    {
        // Need to reverse key order
        u8 tmp, *key = (u8 *)params->key;
        cipher = MAC_CIPHER_WPI_SMS4;
        for (i = 0; i < WPI_SUBKEY_LEN/2; i++) {
            tmp = key[i];
            key[i] = key[WPI_SUBKEY_LEN - 1 - i];
            key[WPI_SUBKEY_LEN - 1 - i] = tmp;
        }
        for (i = 0; i < WPI_SUBKEY_LEN/2; i++) {
            tmp = key[i + WPI_SUBKEY_LEN];
            key[i + WPI_SUBKEY_LEN] = key[WPI_KEY_LEN - 1 - i];
            key[WPI_KEY_LEN - 1 - i] = tmp;
        }
        break;
    }
    case WLAN_CIPHER_SUITE_GCMP:
        cipher = MAC_CIPHER_GCMP_128;
        break;
    case WLAN_CIPHER_SUITE_GCMP_256:
        cipher = MAC_CIPHER_GCMP_256;
        break;
    case WLAN_CIPHER_SUITE_CCMP_256:
        cipher = MAC_CIPHER_CCMP_256;
        break;
    default:
        return -EINVAL;
    }

    if ((error = rwnx_send_key_add(rwnx_hw, vif->vif_index,
                                   (sta ? sta->sta_idx : 0xFF), pairwise,
                                   (u8 *)params->key, params->key_len,
                                   key_index, cipher, &key_add_cfm)))
        return error;

    if (key_add_cfm.status != 0) {
        RWNX_PRINT_CFM_ERR(key_add);
        return -EIO;
    }

    /* Save the index retrieved from LMAC */
    rwnx_key->hw_idx = key_add_cfm.hw_key_idx;

    return 0;
}

/**
 * @get_key: get information about the key with the given parameters.
 *	@mac_addr will be %NULL when requesting information for a group
 *	key. All pointers given to the @callback function need not be valid
 *	after it returns. This function should return an error if it is
 *	not possible to retrieve the key, -ENOENT if it doesn't exist.
 *
 */
static int rwnx_cfg80211_get_key(struct wiphy *wiphy, struct net_device *netdev,
                                 u8 key_index, bool pairwise, const u8 *mac_addr,
                                 void *cookie,
                                 void (*callback)(void *cookie, struct key_params*))
{
    RWNX_DBG(RWNX_FN_ENTRY_STR);

    return -1;
}


/**
 * @del_key: remove a key given the @mac_addr (%NULL for a group key)
 *	and @key_index, return -ENOENT if the key doesn't exist.
 */
static int rwnx_cfg80211_del_key(struct wiphy *wiphy, struct net_device *netdev,
                                 u8 key_index, bool pairwise, const u8 *mac_addr)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *vif = netdev_priv(netdev);
    int error;
    struct rwnx_sta *sta = NULL;
    struct rwnx_key *rwnx_key;

    RWNX_DBG(RWNX_FN_ENTRY_STR);
    if (mac_addr) {
        sta = rwnx_get_sta(rwnx_hw, mac_addr);
        if (!sta)
            return -EINVAL;
        rwnx_key = &sta->key;
    }
    else
        rwnx_key = &vif->key[key_index];

    error = rwnx_send_key_del(rwnx_hw, rwnx_key->hw_idx);

    return error;
}

/**
 * @set_default_key: set the default key on an interface
 */
static int rwnx_cfg80211_set_default_key(struct wiphy *wiphy,
                                         struct net_device *netdev,
                                         u8 key_index, bool unicast, bool multicast)
{
    RWNX_DBG(RWNX_FN_ENTRY_STR);

    return 0;
}

/**
 * @set_default_mgmt_key: set the default management frame key on an interface
 */
static int rwnx_cfg80211_set_default_mgmt_key(struct wiphy *wiphy,
                                              struct net_device *netdev,
                                              u8 key_index)
{
    return 0;
}

/**
 * @connect: Connect to the ESS with the specified parameters. When connected,
 *	call cfg80211_connect_result() with status code %WLAN_STATUS_SUCCESS.
 *	If the connection fails for some reason, call cfg80211_connect_result()
 *	with the status from the AP.
 *	(invoked with the wireless_dev mutex held)
 */
static int rwnx_cfg80211_connect(struct wiphy *wiphy, struct net_device *dev,
                                 struct cfg80211_connect_params *sme)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct sm_connect_cfm sm_connect_cfm;
    int error = 0;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    /* For SHARED-KEY authentication, must install key first */
    if (sme->auth_type == NL80211_AUTHTYPE_SHARED_KEY && sme->key)
    {
        struct key_params key_params;
        key_params.key = sme->key;
        key_params.seq = NULL;
        key_params.key_len = sme->key_len;
        key_params.seq_len = 0;
        key_params.cipher = sme->crypto.cipher_group;
        rwnx_cfg80211_add_key(wiphy, dev, sme->key_idx, false, NULL, &key_params);
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
    else if ((sme->auth_type == NL80211_AUTHTYPE_SAE) &&
             !(sme->flags & CONNECT_REQ_EXTERNAL_AUTH_SUPPORT)) {
        netdev_err(dev, "Doesn't support SAE without external authentication\n");
        return -EINVAL;
    }
#endif

    /* Forward the information to the LMAC */
    if ((error = rwnx_send_sm_connect_req(rwnx_hw, rwnx_vif, sme, &sm_connect_cfm)))
        return error;

    // Check the status
    switch (sm_connect_cfm.status)
    {
        case CO_OK:
            rwnx_save_assoc_info_for_ft(rwnx_vif, sme);
            error = 0;
            break;
        case CO_BUSY:
            error = -EINPROGRESS;
            break;
        case CO_BAD_PARAM:
            error = -EINVAL;
            break;
        case CO_OP_IN_PROGRESS:
            error = -EALREADY;
            break;
        default:
            error = -EIO;
            break;
    }

    return error;
}

/**
 * @disconnect: Disconnect from the BSS/ESS.
 *	(invoked with the wireless_dev mutex held)
 */
static int rwnx_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *dev,
                                    u16 reason_code)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    int error = 0;

    RWNX_DBG(RWNX_FN_ENTRY_STR);
    if (rwnx_hw->scan_request) {
        error = rwnx_cancel_scan(rwnx_hw, rwnx_vif);
        if (error) {
            rwnx_vif->sta.scan_hang = 0;
            printk("cancel scan fail:error = %d\n");
        }
    }
    return(rwnx_send_sm_disconnect_req(rwnx_hw, rwnx_vif, reason_code));
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
/**
 * @external_auth: indicates result of offloaded authentication processing from
 *     user space
 */
static int rwnx_cfg80211_external_auth(struct wiphy *wiphy, struct net_device *dev,
                                       struct cfg80211_external_auth_params *params)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);

    if (!(rwnx_vif->sta.flags & RWNX_STA_EXT_AUTH))
        return -EINVAL;

    rwnx_external_auth_disable(rwnx_vif);
    return rwnx_send_sm_external_auth_required_rsp(rwnx_hw, rwnx_vif,
                                                   params->status);
}
#endif

/**
 * @add_station: Add a new station.
 */
static int rwnx_cfg80211_add_station(struct wiphy *wiphy, struct net_device *dev,
                                     const u8 *mac, struct station_parameters *params)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct me_sta_add_cfm me_sta_add_cfm;
    int error = 0;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    WARN_ON(RWNX_VIF_TYPE(rwnx_vif) == NL80211_IFTYPE_AP_VLAN);

    /* Do not add TDLS station */
    if (params->sta_flags_set & BIT(NL80211_STA_FLAG_TDLS_PEER))
        return 0;

    /* Indicate we are in a STA addition process - This will allow handling
     * potential PS mode change indications correctly
     */
    set_bit(RWNX_DEV_ADDING_STA, &rwnx_hw->flags);

    /* Forward the information to the LMAC */
    if ((error = rwnx_send_me_sta_add(rwnx_hw, params, mac, rwnx_vif->vif_index,
                                      &me_sta_add_cfm)))
        return error;

    // Check the status
    switch (me_sta_add_cfm.status)
    {
        case CO_OK:
        {
            struct rwnx_sta *sta = &rwnx_hw->sta_table[me_sta_add_cfm.sta_idx];
            int tid;
            sta->aid = params->aid;

            sta->sta_idx = me_sta_add_cfm.sta_idx;
            sta->ch_idx = rwnx_vif->ch_index;
            sta->vif_idx = rwnx_vif->vif_index;
            sta->vlan_idx = sta->vif_idx;
            sta->qos = (params->sta_flags_set & BIT(NL80211_STA_FLAG_WME)) != 0;
            sta->ht = params->ht_capa ? 1 : 0;
            sta->vht = params->vht_capa ? 1 : 0;
            sta->acm = 0;
            sta->listen_interval = params->listen_interval;

            if (params->local_pm != NL80211_MESH_POWER_UNKNOWN)
                sta->mesh_pm = params->local_pm;
            else
                sta->mesh_pm = rwnx_vif->ap.next_mesh_pm;
            rwnx_update_mesh_power_mode(rwnx_vif);

            for (tid = 0; tid < NX_NB_TXQ_PER_STA; tid++) {
                int uapsd_bit = rwnx_hwq2uapsd[rwnx_tid2hwq[tid]];
                if (params->uapsd_queues & uapsd_bit)
                    sta->uapsd_tids |= 1 << tid;
                else
                    sta->uapsd_tids &= ~(1 << tid);
            }
            memcpy(sta->mac_addr, mac, ETH_ALEN);
            rwnx_dbgfs_register_sta(rwnx_hw, sta);

            /* Ensure that we won't process PS change or channel switch ind*/
            spin_lock_bh(&rwnx_hw->cb_lock);
            rwnx_txq_sta_init(rwnx_hw, sta, rwnx_txq_vif_get_status(rwnx_vif));
            list_add_tail(&sta->list, &rwnx_vif->ap.sta_list);
            rwnx_vif->generation++;
            sta->valid = true;
            rwnx_ps_bh_enable(rwnx_hw, sta, sta->ps.active || me_sta_add_cfm.pm_state);
            spin_unlock_bh(&rwnx_hw->cb_lock);

            error = 0;

#ifdef CONFIG_RWNX_BFMER
            if (rwnx_hw->mod_params->bfmer)
                rwnx_send_bfmer_enable(rwnx_hw, sta, params->vht_capa);

            rwnx_mu_group_sta_init(sta, params->vht_capa);
#endif /* CONFIG_RWNX_BFMER */

            #define PRINT_STA_FLAG(f)                               \
                (params->sta_flags_set & BIT(NL80211_STA_FLAG_##f) ? "["#f"]" : "")

            netdev_info(dev, "Add sta %d (%pM) flags=%s%s%s%s%s%s%s",
                        sta->sta_idx, mac,
                        PRINT_STA_FLAG(AUTHORIZED),
                        PRINT_STA_FLAG(SHORT_PREAMBLE),
                        PRINT_STA_FLAG(WME),
                        PRINT_STA_FLAG(MFP),
                        PRINT_STA_FLAG(AUTHENTICATED),
                        PRINT_STA_FLAG(TDLS_PEER),
                        PRINT_STA_FLAG(ASSOCIATED));
            #undef PRINT_STA_FLAG
            break;
        }
        default:
            error = -EBUSY;
            break;
    }

    clear_bit(RWNX_DEV_ADDING_STA, &rwnx_hw->flags);

    return error;
}

/**
 * @del_station: Remove a station
 */
static int rwnx_cfg80211_del_station(struct wiphy *wiphy,
                                     struct net_device *dev,
                                     struct station_del_parameters *params)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct rwnx_sta *cur, *tmp;
    int error = 0, found = 0;
    const u8 *mac = NULL;

    if (params)
        mac = params->mac;

    list_for_each_entry_safe(cur, tmp, &rwnx_vif->ap.sta_list, list) {
        if ((!mac) || (!memcmp(cur->mac_addr, mac, ETH_ALEN))) {
            netdev_info(dev, "Del sta %d (%pM)", cur->sta_idx, cur->mac_addr);
            /* Ensure that we won't process PS change ind */
            spin_lock_bh(&rwnx_hw->cb_lock);
            cur->ps.active = false;
            cur->valid = false;
            spin_unlock_bh(&rwnx_hw->cb_lock);

            if (cur->vif_idx != cur->vlan_idx) {
                struct rwnx_vif *vlan_vif;
                vlan_vif = rwnx_hw->vif_table[cur->vlan_idx];
                if (vlan_vif->up) {
                    if ((RWNX_VIF_TYPE(vlan_vif) == NL80211_IFTYPE_AP_VLAN) &&
                        (vlan_vif->use_4addr)) {
                        vlan_vif->ap_vlan.sta_4a = NULL;
                    } else {
                        WARN(1, "Deleting sta belonging to VLAN other than AP_VLAN 4A");
                    }
                }
            }

            rwnx_txq_sta_deinit(rwnx_hw, cur);
            error = rwnx_send_me_sta_del(rwnx_hw, cur->sta_idx, false);
            if ((error != 0) && (error != -EPIPE))
                return error;

#ifdef CONFIG_RWNX_BFMER
            // Disable Beamformer if supported
            rwnx_bfmer_report_del(rwnx_hw, cur);
            rwnx_mu_group_sta_del(rwnx_hw, cur);
#endif /* CONFIG_RWNX_BFMER */

            list_del(&cur->list);
            rwnx_vif->generation++;
            rwnx_dbgfs_unregister_sta(rwnx_hw, cur);
            found ++;
            break;
        }
    }

    if (!found)
        return -ENOENT;

    rwnx_update_mesh_power_mode(rwnx_vif);

    return 0;
}

/**
 * @change_station: Modify a given station. Note that flags changes are not much
 *	validated in cfg80211, in particular the auth/assoc/authorized flags
 *	might come to the driver in invalid combinations -- make sure to check
 *	them, also against the existing state! Drivers must call
 *	cfg80211_check_station_change() to validate the information.
 */
static int rwnx_cfg80211_change_station(struct wiphy *wiphy, struct net_device *dev,
                                        const u8 *mac, struct station_parameters *params)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *vif = netdev_priv(dev);
    struct rwnx_sta *sta;

    sta = rwnx_get_sta(rwnx_hw, mac);
    if (!sta)
    {
        /* Add the TDLS station */
        if (params->sta_flags_set & BIT(NL80211_STA_FLAG_TDLS_PEER))
        {
            struct rwnx_vif *rwnx_vif = netdev_priv(dev);
            struct me_sta_add_cfm me_sta_add_cfm;
            int error = 0;

            /* Indicate we are in a STA addition process - This will allow handling
             * potential PS mode change indications correctly
             */
            set_bit(RWNX_DEV_ADDING_STA, &rwnx_hw->flags);

            /* Forward the information to the LMAC */
            if ((error = rwnx_send_me_sta_add(rwnx_hw, params, mac, rwnx_vif->vif_index,
                                              &me_sta_add_cfm)))
                return error;

            // Check the status
            switch (me_sta_add_cfm.status)
            {
                case CO_OK:
                {
                    int tid;
                    sta = &rwnx_hw->sta_table[me_sta_add_cfm.sta_idx];
                    sta->aid = params->aid;
                    sta->sta_idx = me_sta_add_cfm.sta_idx;
                    sta->ch_idx = rwnx_vif->ch_index;
                    sta->vif_idx = rwnx_vif->vif_index;
                    sta->vlan_idx = sta->vif_idx;
                    sta->qos = (params->sta_flags_set & BIT(NL80211_STA_FLAG_WME)) != 0;
                    sta->ht = params->ht_capa ? 1 : 0;
                    sta->vht = params->vht_capa ? 1 : 0;
                    sta->acm = 0;
                    for (tid = 0; tid < NX_NB_TXQ_PER_STA; tid++) {
                        int uapsd_bit = rwnx_hwq2uapsd[rwnx_tid2hwq[tid]];
                        if (params->uapsd_queues & uapsd_bit)
                            sta->uapsd_tids |= 1 << tid;
                        else
                            sta->uapsd_tids &= ~(1 << tid);
                    }
                    memcpy(sta->mac_addr, mac, ETH_ALEN);
                    rwnx_dbgfs_register_sta(rwnx_hw, sta);

                    /* Ensure that we won't process PS change or channel switch ind*/
                    spin_lock_bh(&rwnx_hw->cb_lock);
                    rwnx_txq_sta_init(rwnx_hw, sta, rwnx_txq_vif_get_status(rwnx_vif));
                    if (rwnx_vif->tdls_status == TDLS_SETUP_RSP_TX) {
                        rwnx_vif->tdls_status = TDLS_LINK_ACTIVE;
                        sta->tdls.initiator = true;
                        sta->tdls.active = true;
                    }
                    /* Set TDLS channel switch capability */
                    if ((params->ext_capab[3] & WLAN_EXT_CAPA4_TDLS_CHAN_SWITCH) &&
                        !rwnx_vif->tdls_chsw_prohibited)
                        sta->tdls.chsw_allowed = true;
                    rwnx_vif->sta.tdls_sta = sta;
                    sta->valid = true;
                    spin_unlock_bh(&rwnx_hw->cb_lock);
#ifdef CONFIG_RWNX_BFMER
                    if (rwnx_hw->mod_params->bfmer)
                        rwnx_send_bfmer_enable(rwnx_hw, sta, params->vht_capa);

                    rwnx_mu_group_sta_init(sta, NULL);
#endif /* CONFIG_RWNX_BFMER */

                    #define PRINT_STA_FLAG(f)                               \
                        (params->sta_flags_set & BIT(NL80211_STA_FLAG_##f) ? "["#f"]" : "")

                    netdev_info(dev, "Add %s TDLS sta %d (%pM) flags=%s%s%s%s%s%s%s",
                                sta->tdls.initiator ? "initiator" : "responder",
                                sta->sta_idx, mac,
                                PRINT_STA_FLAG(AUTHORIZED),
                                PRINT_STA_FLAG(SHORT_PREAMBLE),
                                PRINT_STA_FLAG(WME),
                                PRINT_STA_FLAG(MFP),
                                PRINT_STA_FLAG(AUTHENTICATED),
                                PRINT_STA_FLAG(TDLS_PEER),
                                PRINT_STA_FLAG(ASSOCIATED));
                    #undef PRINT_STA_FLAG

                    break;
                }
                default:
                    //error = -EBUSY;
                    break;
            }

            clear_bit(RWNX_DEV_ADDING_STA, &rwnx_hw->flags);
        } else  {
            return -EINVAL;
        }
    }

    if (params->sta_flags_mask & BIT(NL80211_STA_FLAG_AUTHORIZED))
        rwnx_send_me_set_control_port_req(rwnx_hw,
                (params->sta_flags_set & BIT(NL80211_STA_FLAG_AUTHORIZED)) != 0,
                sta->sta_idx);

    if (RWNX_VIF_TYPE(vif) == NL80211_IFTYPE_MESH_POINT) {
        if (params->sta_modify_mask & STATION_PARAM_APPLY_PLINK_STATE) {
            if (params->plink_state < NUM_NL80211_PLINK_STATES) {
                rwnx_send_mesh_peer_update_ntf(rwnx_hw, vif, sta->sta_idx, params->plink_state);
            }
        }

        if (params->local_pm != NL80211_MESH_POWER_UNKNOWN) {
            sta->mesh_pm = params->local_pm;
            rwnx_update_mesh_power_mode(vif);
        }
    }

    if (params->vlan) {
        uint8_t vlan_idx;

        vif = netdev_priv(params->vlan);
        vlan_idx = vif->vif_index;

        if (sta->vlan_idx != vlan_idx) {
            struct rwnx_vif *old_vif;
            old_vif = rwnx_hw->vif_table[sta->vlan_idx];
            rwnx_txq_sta_switch_vif(sta, old_vif, vif);
            sta->vlan_idx = vlan_idx;

            if ((RWNX_VIF_TYPE(vif) == NL80211_IFTYPE_AP_VLAN) &&
                (vif->use_4addr)) {
                WARN((vif->ap_vlan.sta_4a),
                     "4A AP_VLAN interface with more than one sta");
                vif->ap_vlan.sta_4a = sta;
            }

            if ((RWNX_VIF_TYPE(old_vif) == NL80211_IFTYPE_AP_VLAN) &&
                (old_vif->use_4addr)) {
                old_vif->ap_vlan.sta_4a = NULL;
            }
        }
    }

    return 0;
}

/**
 * @start_ap: Start acting in AP mode defined by the parameters.
 */
static int rwnx_cfg80211_start_ap(struct wiphy *wiphy, struct net_device *dev,
                                  struct cfg80211_ap_settings *settings)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct apm_start_cfm apm_start_cfm;
    struct rwnx_sta *sta;
    int error = 0;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    if ((error = rwnx_send_apm_start_req(rwnx_hw, rwnx_vif, settings,
                                         &apm_start_cfm)))
        goto end;

    // Check the status
    switch (apm_start_cfm.status)
    {
        case CO_OK:
        {
            u8 txq_status = 0;
            rwnx_vif->ap.bcmc_index = apm_start_cfm.bcmc_idx;
            rwnx_vif->ap.flags = 0;
            rwnx_vif->ap.bcn_interval = settings->beacon_interval;
            sta = &rwnx_hw->sta_table[apm_start_cfm.bcmc_idx];
            sta->valid = true;
            sta->aid = 0;
            sta->sta_idx = apm_start_cfm.bcmc_idx;
            sta->ch_idx = apm_start_cfm.ch_idx;
            sta->vif_idx = rwnx_vif->vif_index;
            sta->qos = false;
            sta->acm = 0;
            sta->ps.active = false;
            sta->listen_interval = 5;
            rwnx_mu_group_sta_init(sta, NULL);
            spin_lock_bh(&rwnx_hw->cb_lock);
            rwnx_chanctx_link(rwnx_vif, apm_start_cfm.ch_idx,
                              &settings->chandef);
            if (rwnx_hw->cur_chanctx != apm_start_cfm.ch_idx) {
                txq_status = RWNX_TXQ_STOP_CHAN;
            }
            rwnx_txq_vif_init(rwnx_hw, rwnx_vif, txq_status);
            spin_unlock_bh(&rwnx_hw->cb_lock);

            netif_tx_start_all_queues(dev);
            netif_carrier_on(dev);
            error = 0;
            /* If the AP channel is already the active, we probably skip radar
               activation on MM_CHANNEL_SWITCH_IND (unless another vif use this
               ctxt). In anycase retest if radar detection must be activated
             */
            if (txq_status == 0) {
                rwnx_radar_detection_enable_on_cur_channel(rwnx_hw);
            }
            break;
        }
        case CO_BUSY:
            error = -EINPROGRESS;
            break;
        case CO_OP_IN_PROGRESS:
            error = -EALREADY;
            break;
        default:
            error = -EIO;
            break;
    }

end:
    if (error) {
        netdev_info(dev, "Failed to start AP (%d)", error);
    } else {
        netdev_info(dev, "AP started: ch=%d, bcmc_idx=%d",
                    rwnx_vif->ch_index, rwnx_vif->ap.bcmc_index);
    }

    return error;
}


/**
 * @change_beacon: Change the beacon parameters for an access point mode
 *	interface. This should reject the call when AP mode wasn't started.
 */
static int rwnx_cfg80211_change_beacon(struct wiphy *wiphy, struct net_device *dev,
                                       struct cfg80211_beacon_data *info)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *vif = netdev_priv(dev);
    struct rwnx_bcn *bcn = &vif->ap.bcn;
    struct rwnx_ipc_buf buf;
    u8 *bcn_buf;
    int error = 0;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    // Build the beacon
    bcn_buf = rwnx_build_bcn(bcn, info);
    if (!bcn_buf)
        return -ENOMEM;

    // Sync buffer for FW
    if ((error = rwnx_ipc_buf_a2e_init(rwnx_hw, &buf, bcn_buf, bcn->len))) {
        netdev_err(dev, "Failed to allocate IPC buf for new beacon\n");
        kfree(bcn_buf);
        return error;
    }

    // Forward the information to the LMAC
    error = rwnx_send_bcn_change(rwnx_hw, vif->vif_index, buf.dma_addr,
                                 bcn->len, bcn->head_len, bcn->tim_len, NULL);

    rwnx_ipc_buf_dealloc(rwnx_hw, &buf);
    return error;
}

/**
 * * @stop_ap: Stop being an AP, including stopping beaconing.
 */
static int rwnx_cfg80211_stop_ap(struct wiphy *wiphy, struct net_device *dev)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    //struct rwnx_sta *sta;

    rwnx_radar_cancel_cac(&rwnx_hw->radar);
    rwnx_send_apm_stop_req(rwnx_hw, rwnx_vif);
    spin_lock_bh(&rwnx_hw->cb_lock);
    rwnx_chanctx_unlink(rwnx_vif);
    spin_unlock_bh(&rwnx_hw->cb_lock);

    /* delete any remaining STA*/
    while (!list_empty(&rwnx_vif->ap.sta_list)) {
        rwnx_cfg80211_del_station(wiphy, dev, NULL);
    }

    /* delete BC/MC STA */
    //sta = &rwnx_hw->sta_table[rwnx_vif->ap.bcmc_index];
    rwnx_txq_vif_deinit(rwnx_hw, rwnx_vif);
    rwnx_del_bcn(&rwnx_vif->ap.bcn);
    rwnx_del_csa(rwnx_vif);

    netif_tx_stop_all_queues(dev);
    netif_carrier_off(dev);

    netdev_info(dev, "AP Stopped");

    return 0;
}

/**
 * @set_monitor_channel: Set the monitor mode channel for the device. If other
 *	interfaces are active this callback should reject the configuration.
 *	If no interfaces are active or the device is down, the channel should
 *	be stored for when a monitor interface becomes active.
 *
 * Also called internaly with chandef set to NULL simply to retrieve the channel
 * configured at firmware level.
 */
static int rwnx_cfg80211_set_monitor_channel(struct wiphy *wiphy,
                                             struct cfg80211_chan_def *chandef)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif;
    struct me_config_monitor_cfm cfm;
    RWNX_DBG(RWNX_FN_ENTRY_STR);

    if (rwnx_hw->monitor_vif == RWNX_INVALID_VIF)
        return -EINVAL;

    rwnx_vif = rwnx_hw->vif_table[rwnx_hw->monitor_vif];

    // Do nothing if monitor interface is already configured with the requested channel
    if (rwnx_chanctx_valid(rwnx_hw, rwnx_vif->ch_index)) {
        struct rwnx_chanctx *ctxt;
        ctxt = &rwnx_vif->rwnx_hw->chanctx_table[rwnx_vif->ch_index];
        if (chandef && cfg80211_chandef_identical(&ctxt->chan_def, chandef))
            return 0;
    }

    // Always send command to firmware. It allows to retrieve channel context index
    // and its configuration.
    if (rwnx_send_config_monitor_req(rwnx_hw, chandef, &cfm))
        return -EIO;

    // Always re-set channel context info
    rwnx_chanctx_unlink(rwnx_vif);



    // If there is also a STA interface not yet connected then monitor interface
    // will only have a channel context after the connection of the STA interface.
    if (cfm.chan_index != RWNX_CH_NOT_SET)
    {
        struct cfg80211_chan_def mon_chandef;

        if (rwnx_hw->vif_started > 1) {
            // In this case we just want to update the channel context index not
            // the channel configuration
            rwnx_chanctx_link(rwnx_vif, cfm.chan_index, NULL);
            return -EBUSY;
        }

        memset(&mon_chandef, 0, sizeof(mon_chandef));
        mon_chandef.chan = ieee80211_get_channel(wiphy, cfm.chan.prim20_freq);
        mon_chandef.center_freq1 = cfm.chan.center1_freq;
        mon_chandef.center_freq2 = cfm.chan.center2_freq;
        mon_chandef.width = (enum nl80211_chan_width)chnl2bw[cfm.chan.type];
        rwnx_chanctx_link(rwnx_vif, cfm.chan_index, &mon_chandef);
    }

    return 0;
}

/**
 * @probe_client: probe an associated client, must return a cookie that it
 *	later passes to cfg80211_probe_status().
 */
int rwnx_cfg80211_probe_client(struct wiphy *wiphy, struct net_device *dev,
                               const u8 *peer, u64 *cookie)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *vif = netdev_priv(dev);
    struct rwnx_sta *sta = NULL;
    struct apm_probe_client_cfm cfm;

    if ((RWNX_VIF_TYPE(vif) != NL80211_IFTYPE_AP) &&
        (RWNX_VIF_TYPE(vif) != NL80211_IFTYPE_AP_VLAN) &&
        (RWNX_VIF_TYPE(vif) != NL80211_IFTYPE_P2P_GO) &&
        (RWNX_VIF_TYPE(vif) != NL80211_IFTYPE_MESH_POINT))
        return -EINVAL;

    list_for_each_entry(sta, &vif->ap.sta_list, list) {
        if (sta->valid && ether_addr_equal(sta->mac_addr, peer))
            break;
    }

    if (!sta)
        return -EINVAL;

    rwnx_send_apm_probe_req(rwnx_hw, vif, sta, &cfm);

    if (cfm.status != CO_OK)
        return -EINVAL;

    *cookie = (u64)cfm.probe_id;
    return 0;
}

/**
 * @set_wiphy_params: Notify that wiphy parameters have changed;
 *	@changed bitfield (see &enum wiphy_params_flags) describes which values
 *	have changed. The actual parameter values are available in
 *	struct wiphy. If returning an error, no value should be changed.
 */
static int rwnx_cfg80211_set_wiphy_params(struct wiphy *wiphy, u32 changed)
{
    return 0;
}


/**
 * @set_tx_power: set the transmit power according to the parameters,
 *	the power passed is in mBm, to get dBm use MBM_TO_DBM(). The
 *	wdev may be %NULL if power was set for the wiphy, and will
 *	always be %NULL unless the driver supports per-vif TX power
 *	(as advertised by the nl80211 feature flag.)
 */
static int rwnx_cfg80211_set_tx_power(struct wiphy *wiphy, struct wireless_dev *wdev,
                                      enum nl80211_tx_power_setting type, int mbm)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *vif;
    s8 pwr;
    int res = 0;

    if (type == NL80211_TX_POWER_AUTOMATIC) {
        pwr = 0x7f;
    } else {
        pwr = MBM_TO_DBM(mbm);
    }

    if (wdev) {
        vif = container_of(wdev, struct rwnx_vif, wdev);
        res = rwnx_send_set_power(rwnx_hw, vif->vif_index, pwr, NULL);
    } else {
        list_for_each_entry(vif, &rwnx_hw->vifs, list) {
            res = rwnx_send_set_power(rwnx_hw, vif->vif_index, pwr, NULL);
            if (res)
                break;
        }
    }

    return res;
}

/**
 * @set_power_mgmt: set the power save to one of those two modes:
 *  Power-save off
 *  Power-save on - Dynamic mode
 */
static int rwnx_cfg80211_set_power_mgmt(struct wiphy *wiphy,
                                        struct net_device *dev,
                                        bool enabled, int timeout)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    u8 ps_mode;

    RWNX_DBG(RWNX_FN_ENTRY_STR);
    if (timeout >= 0)
        netdev_info(dev, "Ignore timeout value %d", timeout);

    if (!(rwnx_hw->version_cfm.features & BIT(MM_FEAT_PS_BIT)))
        enabled = false;

    if (enabled) {
        /* Switch to Dynamic Power Save */
        ps_mode = MM_PS_MODE_ON_DYN;
    } else {
        /* Exit Power Save */
        ps_mode = MM_PS_MODE_OFF;
    }

    /* TODO:
     * Enable power save mode which will cause STA
     * connect/disconnect repeating.
     * For stability, temporarily closed power save mode.
     * */
    //return rwnx_send_me_set_ps_mode(rwnx_hw, ps_mode);
    return rwnx_send_me_set_ps_mode(rwnx_hw, MM_PS_MODE_OFF);
}

/**
 * @set_txq_params: Set TX queue parameters
 */
static int rwnx_cfg80211_set_txq_params(struct wiphy *wiphy, struct net_device *dev,
                                        struct ieee80211_txq_params *params)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    u8 hw_queue, aifs, cwmin, cwmax;
    u32 param;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    hw_queue = rwnx_ac2hwq[0][params->ac];

    aifs  = params->aifs;
    cwmin = fls(params->cwmin);
    cwmax = fls(params->cwmax);

    /* Store queue information in general structure */
    param  = (u32) (aifs << 0);
    param |= (u32) (cwmin << 4);
    param |= (u32) (cwmax << 8);
    param |= (u32) (params->txop) << 12;

    /* Send the MM_SET_EDCA_REQ message to the FW */
    return rwnx_send_set_edca(rwnx_hw, hw_queue, param, false, rwnx_vif->vif_index);
}


/**
 * @remain_on_channel: Request the driver to remain awake on the specified
 *	channel for the specified duration to complete an off-channel
 *	operation (e.g., public action frame exchange). When the driver is
 *	ready on the requested channel, it must indicate this with an event
 *	notification by calling cfg80211_ready_on_channel().
 */
static int
rwnx_cfg80211_remain_on_channel(struct wiphy *wiphy, struct wireless_dev *wdev,
                                struct ieee80211_channel *chan,
                                unsigned int duration, u64 *cookie)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(wdev->netdev);
    struct rwnx_roc *roc;
    int error;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    /* For debug purpose (use ftrace kernel option) */
    trace_roc(rwnx_vif->vif_index, chan->center_freq, duration);

    /* Check that no other RoC procedure has been launched */
    if (rwnx_hw->roc)
        return -EBUSY;

    /* Allocate a temporary RoC element */
    roc = kmalloc(sizeof(struct rwnx_roc), GFP_KERNEL);
    if (!roc)
        return -ENOMEM;

    /* Initialize the RoC information element */
    roc->vif = rwnx_vif;
    roc->chan = chan;
    roc->duration = duration;
    roc->internal = false;
    roc->on_chan = false;
    roc->tx_cnt = 0;
    memset(roc->tx_cookie, 0, sizeof(roc->tx_cookie));

    /* Initialize the OFFCHAN TX queue to allow off-channel transmissions */
    rwnx_txq_offchan_init(rwnx_vif);

    /* Forward the information to the FMAC */
    rwnx_hw->roc = roc;
    error = rwnx_send_roc(rwnx_hw, rwnx_vif, chan, duration);

    if (error) {
        kfree(roc);
        rwnx_hw->roc = NULL;
        rwnx_txq_offchan_deinit(rwnx_vif);
    } else if (cookie)
        *cookie = (u64)roc;

    return error;
}

/**
 * @cancel_remain_on_channel: Cancel an on-going remain-on-channel operation.
 *	This allows the operation to be terminated prior to timeout based on
 *	the duration value.
 */
static int rwnx_cfg80211_cancel_remain_on_channel(struct wiphy *wiphy,
                                                  struct wireless_dev *wdev,
                                                  u64 cookie)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(wdev->netdev);

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    trace_cancel_roc(rwnx_vif->vif_index);

    if (!rwnx_hw->roc)
        return 0;

    if (cookie != (u64)rwnx_hw->roc)
        return -EINVAL;

    /* Forward the information to the FMAC */
    return rwnx_send_cancel_roc(rwnx_hw);
}

/**
 * @dump_survey: get site survey information.
 */
static int rwnx_cfg80211_dump_survey(struct wiphy *wiphy, struct net_device *netdev,
                                     int idx, struct survey_info *info)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct ieee80211_supported_band *sband;
    struct rwnx_survey_info *rwnx_survey;

    //RWNX_DBG(RWNX_FN_ENTRY_STR);

    if (idx >= ARRAY_SIZE(rwnx_hw->survey))
        return -ENOENT;

    rwnx_survey = &rwnx_hw->survey[idx];

    // Check if provided index matches with a supported 2.4GHz channel
    sband = wiphy->bands[NL80211_BAND_2GHZ];
    if (sband && idx >= sband->n_channels) {
        idx -= sband->n_channels;
        sband = NULL;
    }

    if (!sband) {
        // Check if provided index matches with a supported 5GHz channel
        sband = wiphy->bands[NL80211_BAND_5GHZ];

        if (!sband || idx >= sband->n_channels)
            return -ENOENT;
    }

    // Fill the survey
    info->channel = &sband->channels[idx];
    info->filled = rwnx_survey->filled;

    if (rwnx_survey->filled != 0) {
        info->time = (u64)rwnx_survey->chan_time_ms;
        info->time_busy = (u64)rwnx_survey->chan_time_busy_ms;
        info->noise = rwnx_survey->noise_dbm;

        // TODO: clear survey after some time ?
    }

    return 0;
}

/**
 * @get_channel: Get the current operating channel for the virtual interface.
 *	For monitor interfaces, it should return %NULL unless there's a single
 *	current monitoring channel.
 */
static int rwnx_cfg80211_get_channel(struct wiphy *wiphy,
                                     struct wireless_dev *wdev,
                                     struct cfg80211_chan_def *chandef) {
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = container_of(wdev, struct rwnx_vif, wdev);
    struct rwnx_chanctx *ctxt;

    if (!rwnx_vif->up) {
        return -ENODATA;
    }

    if (rwnx_vif->vif_index == rwnx_hw->monitor_vif)
    {
        //retrieve channel from firmware
        rwnx_cfg80211_set_monitor_channel(wiphy, NULL);
    }

    //Check if channel context is valid
    if(!rwnx_chanctx_valid(rwnx_hw, rwnx_vif->ch_index)){
        return -ENODATA;
    }

    ctxt = &rwnx_hw->chanctx_table[rwnx_vif->ch_index];
    *chandef = ctxt->chan_def;

    return 0;
}

/**
 * @mgmt_tx: Transmit a management frame.
 */
static int rwnx_cfg80211_mgmt_tx(struct wiphy *wiphy, struct wireless_dev *wdev,
                                 struct cfg80211_mgmt_tx_params *params,
                                 u64 *cookie)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(wdev->netdev);
    struct rwnx_sta *rwnx_sta;
    struct ieee80211_mgmt *mgmt = (void *)params->buf;
    bool ap = false;
    bool offchan = false;
    int res;

    switch (RWNX_VIF_TYPE(rwnx_vif)) {
        case NL80211_IFTYPE_AP_VLAN:
            rwnx_vif = rwnx_vif->ap_vlan.master;
        case NL80211_IFTYPE_AP:
        case NL80211_IFTYPE_P2P_GO:
        case NL80211_IFTYPE_MESH_POINT:
            ap = true;
            break;
        case NL80211_IFTYPE_STATION:
        case NL80211_IFTYPE_P2P_CLIENT:
        default:
            break;
    }

    // Get STA on which management frame has to be sent
    rwnx_sta = rwnx_retrieve_sta(rwnx_hw, rwnx_vif, mgmt->da,
                                 mgmt->frame_control, ap);

    if (params->offchan) {
        if (!params->chan)
            return -EINVAL;

        offchan = true;
        if (rwnx_chanctx_valid(rwnx_hw, rwnx_vif->ch_index)) {
            struct rwnx_chanctx *ctxt = &rwnx_hw->chanctx_table[rwnx_vif->ch_index];
            if (ctxt->chan_def.chan->center_freq == params->chan->center_freq)
                offchan = false;
        }
    }

    trace_mgmt_tx((offchan) ? params->chan->center_freq : 0,
                  rwnx_vif->vif_index, (rwnx_sta) ? rwnx_sta->sta_idx : 0xFF,
                  mgmt);

    if (offchan) {
        // Offchannel transmission, need to start a RoC
        if (rwnx_hw->roc) {
            // Test if current RoC can be re-used
            if ((rwnx_hw->roc->vif != rwnx_vif) ||
                (rwnx_hw->roc->chan->center_freq != params->chan->center_freq))
                return -EINVAL;
            // TODO: inform FW to increase RoC duration
        } else {
            int error;
            unsigned int duration = 30;

            /* Start a new ROC procedure */
            if (params->wait)
                duration = params->wait;

            error = rwnx_cfg80211_remain_on_channel(wiphy, wdev, params->chan,
                                                    duration, NULL);
            if (error)
                return error;

            // internal RoC, no need to inform user space about it
            rwnx_hw->roc->internal = true;
        }
    }

    res = rwnx_start_mgmt_xmit(rwnx_vif, rwnx_sta, params, offchan, cookie);
    if (offchan) {
        if (rwnx_hw->roc->tx_cnt < NX_ROC_TX)
            rwnx_hw->roc->tx_cookie[rwnx_hw->roc->tx_cnt] = *cookie;
        else
            wiphy_warn(wiphy, "%d frames sent within the same Roc (> NX_ROC_TX)",
                       rwnx_hw->roc->tx_cnt + 1);
        rwnx_hw->roc->tx_cnt++;
    }
    return res;
}

int rwnx_cfg80211_mgmt_tx_cancel_wait(struct wiphy *wiphy,
				       struct wireless_dev *wdev,
				       u64 cookie)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    int i, nb_tx_cookie = 0;

    if (!rwnx_hw->roc || !rwnx_hw->roc->tx_cnt)
        return 0;

    for (i = 0; i < NX_ROC_TX; i++) {
        if (!rwnx_hw->roc->tx_cookie[i])
            continue;

        nb_tx_cookie++;
        if (rwnx_hw->roc->tx_cookie[i] == cookie) {
            rwnx_hw->roc->tx_cookie[i] = 0;
            rwnx_hw->roc->tx_cnt--;
            break;
        }
    }

    if (i == NX_ROC_TX) {
        // Didn't find the cookie but this frame may still have been sent within this
        // Roc if more than NX_ROC_TX frame have been sent
        if (nb_tx_cookie != rwnx_hw->roc->tx_cnt)
            rwnx_hw->roc->tx_cnt--;
        else
            return 0;
    }

    // Stop the RoC if started to send TX frame and all frames have been "wait cancelled"
    if ((!rwnx_hw->roc->internal) || (rwnx_hw->roc->tx_cnt > 0))
        return 0;

    return rwnx_cfg80211_cancel_remain_on_channel(wiphy, wdev, (u64)rwnx_hw->roc);
}

/**
 * @start_radar_detection: Start radar detection in the driver.
 */
static int rwnx_cfg80211_start_radar_detection(struct wiphy *wiphy,
                                               struct net_device *dev,
                                               struct cfg80211_chan_def *chandef,
                                               u32 cac_time_ms)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct apm_start_cac_cfm cfm;

    rwnx_radar_start_cac(&rwnx_hw->radar, cac_time_ms, rwnx_vif);
    rwnx_send_apm_start_cac_req(rwnx_hw, rwnx_vif, chandef, &cfm);

    if (cfm.status == CO_OK) {
        spin_lock_bh(&rwnx_hw->cb_lock);
        rwnx_chanctx_link(rwnx_vif, cfm.ch_idx, chandef);
        if (rwnx_hw->cur_chanctx == rwnx_vif->ch_index)
            rwnx_radar_detection_enable(&rwnx_hw->radar,
                                        RWNX_RADAR_DETECT_REPORT,
                                        RWNX_RADAR_RIU);
        spin_unlock_bh(&rwnx_hw->cb_lock);
    } else {
        return -EIO;
    }

    return 0;
}

/**
 * @update_ft_ies: Provide updated Fast BSS Transition information to the
 *	driver. If the SME is in the driver/firmware, this information can be
 *	used in building Authentication and Reassociation Request frames.
 */
static int rwnx_cfg80211_update_ft_ies(struct wiphy *wiphy,
                                       struct net_device *dev,
                                       struct cfg80211_update_ft_ies_params *ftie)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *vif = netdev_priv(dev);
    const struct element *rsne = NULL, *mde = NULL, *fte = NULL, *elem;
    bool ft_in_non_rsn = false;
    int fties_len = 0;
    u8 *ft_assoc_ies, *pos;

    if ((RWNX_VIF_TYPE(vif) != NL80211_IFTYPE_STATION) ||
        (vif->sta.ft_assoc_ies == NULL))
        return 0;

    for_each_element(elem, ftie->ie, ftie->ie_len) {
        if (elem->id == WLAN_EID_RSN)
            rsne = elem;
        else if (elem->id == WLAN_EID_MOBILITY_DOMAIN)
            mde = elem;
        else if (elem->id == WLAN_EID_FAST_BSS_TRANSITION)
            fte = elem;
        else
            netdev_warn(dev, "Unexpected FT element %d\n", elem->id);
    }
    if (!mde) {
        // maybe just test MDE for
        netdev_warn(dev, "Didn't find Mobility_Domain Element\n");
        return 0;
    } else if (!rsne && !fte) {
        // not sure this happen in real life ...
        ft_in_non_rsn = true;
    } else if (!rsne || !fte) {
        netdev_warn(dev, "Didn't find RSN or Fast Transition Element\n");
        return 0;
    }

    for_each_element(elem, vif->sta.ft_assoc_ies, vif->sta.ft_assoc_ies_len) {
        if ((elem->id == WLAN_EID_RSN) ||
            (elem->id == WLAN_EID_MOBILITY_DOMAIN) ||
            (elem->id == WLAN_EID_FAST_BSS_TRANSITION))
            fties_len += elem->datalen + sizeof(struct element);
    }

    ft_assoc_ies = kmalloc(vif->sta.ft_assoc_ies_len - fties_len + ftie->ie_len,
                        GFP_KERNEL);
    if (!ft_assoc_ies) {
        netdev_warn(dev, "Fail to allocate buffer for association elements");
        return 0;
    }

    // Recopy current Association Elements one at a time and replace FT
    // element with updated version.
    pos = ft_assoc_ies;
    for_each_element(elem, vif->sta.ft_assoc_ies, vif->sta.ft_assoc_ies_len) {
        if (elem->id == WLAN_EID_RSN) {
            if (ft_in_non_rsn) {
                netdev_warn(dev, "Found RSN element in non RSN FT");
                goto abort;
            } else if (!rsne) {
                netdev_warn(dev, "Found several RSN element");
                goto abort;
            } else {
                memcpy(pos, rsne, sizeof(*rsne) + rsne->datalen);
                pos += sizeof(*rsne) + rsne->datalen;
                rsne = NULL;
            }
        } else if (elem->id == WLAN_EID_MOBILITY_DOMAIN) {
            if (!mde) {
                netdev_warn(dev, "Found several Mobility Domain element");
                goto abort;
            } else {
                memcpy(pos, mde, sizeof(*mde) + mde->datalen);
                pos += sizeof(*mde) + mde->datalen;
                mde = NULL;
            }
        }
        else if (elem->id == WLAN_EID_FAST_BSS_TRANSITION) {
            if (ft_in_non_rsn) {
                netdev_warn(dev, "Found Fast Transition element in non RSN FT");
                goto abort;
            } else if (!fte) {
                netdev_warn(dev, "found several Fast Transition element");
                goto abort;
            } else {
                memcpy(pos, fte, sizeof(*fte) + fte->datalen);
                pos += sizeof(*fte) + fte->datalen;
                fte = NULL;
            }
        }
        else {
            // Put FTE after MDE if non present in Association Element
            if (fte && !mde) {
                memcpy(pos, fte, sizeof(*fte) + fte->datalen);
                pos += sizeof(*fte) + fte->datalen;
                fte = NULL;
            }
            memcpy(pos, elem, sizeof(*elem) + elem->datalen);
            pos += sizeof(*elem) + elem->datalen;
        }
    }
    if (fte) {
        memcpy(pos, fte, sizeof(*fte) + fte->datalen);
        pos += sizeof(*fte) + fte->datalen;
        //fte = NULL;
    }

    kfree(vif->sta.ft_assoc_ies);
    vif->sta.ft_assoc_ies = ft_assoc_ies;
    vif->sta.ft_assoc_ies_len = pos - ft_assoc_ies;

    if (vif->sta.flags & RWNX_STA_FT_OVER_DS) {
        struct sm_connect_cfm sm_connect_cfm;
        struct cfg80211_connect_params sme;

        memset(&sme, 0, sizeof(sme));
        rsne = cfg80211_find_elem(WLAN_EID_RSN, vif->sta.ft_assoc_ies,
                                  vif->sta.ft_assoc_ies_len);
        if (rsne && rwnx_rsne_to_connect_params(rsne, &sme)) {
            netdev_warn(dev, "FT RSN parsing failed\n");
            return 0;
        }

        sme.ssid_len = vif->sta.ft_assoc_ies[1];
        sme.ssid = &vif->sta.ft_assoc_ies[2];
        sme.bssid = vif->sta.ft_target_ap;
        sme.ie = &vif->sta.ft_assoc_ies[2 + sme.ssid_len];
        sme.ie_len = vif->sta.ft_assoc_ies_len - (2 + sme.ssid_len);
        sme.auth_type = NL80211_AUTHTYPE_FT;
        rwnx_send_sm_connect_req(rwnx_hw, vif, &sme, &sm_connect_cfm);
        vif->sta.flags &= ~RWNX_STA_FT_OVER_DS;

    } else if (vif->sta.flags & RWNX_STA_FT_OVER_AIR) {
        uint8_t ssid_len;
        vif->sta.flags &= ~RWNX_STA_FT_OVER_AIR;

        // Skip the first element (SSID)
        ssid_len = vif->sta.ft_assoc_ies[1] + 2;
        if (rwnx_send_sm_ft_auth_rsp(rwnx_hw, vif, &vif->sta.ft_assoc_ies[ssid_len],
                                     vif->sta.ft_assoc_ies_len - ssid_len))
            netdev_err(dev, "FT Over Air: Failed to send updated assoc elem\n");
    }

    return 0;

abort:
    kfree(ft_assoc_ies);
    return 0;
}

/**
 * @set_cqm_rssi_config: Configure connection quality monitor RSSI threshold.
 */
static int rwnx_cfg80211_set_cqm_rssi_config(struct wiphy *wiphy,
                                             struct net_device *dev,
                                             int32_t rssi_thold, uint32_t rssi_hyst)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);

    return rwnx_send_cfg_rssi_req(rwnx_hw, rwnx_vif->vif_index, rssi_thold, rssi_hyst);
}

/**
 *
 * @channel_switch: initiate channel-switch procedure (with CSA). Driver is
 *	responsible for veryfing if the switch is possible. Since this is
 *	inherently tricky driver may decide to disconnect an interface later
 *	with cfg80211_stop_iface(). This doesn't mean driver can accept
 *	everything. It should do it's best to verify requests and reject them
 *	as soon as possible.
 */
static int rwnx_cfg80211_channel_switch(struct wiphy *wiphy,
                                        struct net_device *dev,
                                        struct cfg80211_csa_settings *params)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *vif = netdev_priv(dev);
    struct rwnx_ipc_buf buf;
    struct rwnx_bcn *bcn, *bcn_after;
    struct rwnx_csa *csa;
    u16 csa_oft[BCN_MAX_CSA_CPT];
    u8 *bcn_buf;
    int i, error = 0;


    if (vif->ap.csa)
        return -EBUSY;

    if (params->n_counter_offsets_beacon > BCN_MAX_CSA_CPT)
        return -EINVAL;

    /* Build the new beacon with CSA IE */
    bcn = &vif->ap.bcn;
    bcn_buf = rwnx_build_bcn(bcn, &params->beacon_csa);
    if (!bcn_buf)
        return -ENOMEM;

    memset(csa_oft, 0, sizeof(csa_oft));
    for (i = 0; i < params->n_counter_offsets_beacon; i++)
    {
        csa_oft[i] = params->counter_offsets_beacon[i] + bcn->head_len +
            bcn->tim_len;
    }

    /* If count is set to 0 (i.e anytime after this beacon) force it to 2 */
    if (params->count == 0) {
        params->count = 2;
        for (i = 0; i < params->n_counter_offsets_beacon; i++)
        {
            bcn_buf[csa_oft[i]] = 2;
        }
    }

    if ((error = rwnx_ipc_buf_a2e_init(rwnx_hw, &buf, bcn_buf, bcn->len))) {
        netdev_err(dev, "Failed to allocate IPC buf for CSA beacon\n");
        kfree(bcn_buf);
        return error;
    }

    /* Build the beacon to use after CSA. It will only be sent to fw once
       CSA is over, but do it before sending the beacon as it must be ready
       when CSA is finished. */
    csa = kzalloc(sizeof(struct rwnx_csa), GFP_KERNEL);
    if (!csa) {
        error = -ENOMEM;
        goto end;
    }
    memset(csa, 0, sizeof(struct rwnx_csa));
    bcn_after = &csa->bcn;
    bcn_buf = rwnx_build_bcn(bcn_after, &params->beacon_after);
    if (!bcn_buf) {
        error = -ENOMEM;
        rwnx_del_csa(vif);
        goto end;
    }

    if ((error = rwnx_ipc_buf_a2e_init(rwnx_hw, &csa->buf, bcn_buf, bcn_after->len))) {
        netdev_err(dev, "Failed to allocate IPC buf for after CSA beacon\n");
        kfree(bcn_buf);
        goto end;
    }

    vif->ap.csa = csa;
    csa->vif = vif;
    csa->chandef = params->chandef;

    /* Send new Beacon. FW will extract channel and count from the beacon */
    error = rwnx_send_bcn_change(rwnx_hw, vif->vif_index, buf.dma_addr,
                                 bcn->len, bcn->head_len, bcn->tim_len, csa_oft);

    if (error) {
        rwnx_del_csa(vif);
    } else {
        INIT_WORK(&csa->work, rwnx_csa_finish);
        cfg80211_ch_switch_started_notify(dev, &csa->chandef, params->count);
    }

  end:
    rwnx_ipc_buf_dealloc(rwnx_hw, &buf);
    /* coverity[leaked_storage] - csa have added to list */
    return error;
}


/**
 * @@tdls_mgmt: Transmit a TDLS management frame.
 */
static int rwnx_cfg80211_tdls_mgmt(struct wiphy *wiphy, struct net_device *dev,
                                   const u8 *peer, u8 action_code,  u8 dialog_token,
                                   u16 status_code, u32 peer_capability,
                                   bool initiator, const u8 *buf, size_t len)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    int ret = 0;

    /* make sure we support TDLS */
    if (!(wiphy->flags & WIPHY_FLAG_SUPPORTS_TDLS))
        return -ENOTSUPP;

    /* make sure we are in station mode (and connected) */
    if ((RWNX_VIF_TYPE(rwnx_vif) != NL80211_IFTYPE_STATION) ||
        (!rwnx_vif->up) || (!rwnx_vif->sta.ap))
        return -ENOTSUPP;

    /* only one TDLS link is supported */
    if ((action_code == WLAN_TDLS_SETUP_REQUEST) &&
        (rwnx_vif->sta.tdls_sta) &&
        (rwnx_vif->tdls_status == TDLS_LINK_ACTIVE)) {
        printk("%s: only one TDLS link is supported!\n", __func__);
        return -ENOTSUPP;
    }

    if ((action_code == WLAN_TDLS_DISCOVERY_REQUEST) &&
        (rwnx_hw->mod_params->ps_on)) {
        printk("%s: discovery request is not supported when "
                "power-save is enabled!\n", __func__);
        return -ENOTSUPP;
    }

    switch (action_code) {
    case WLAN_TDLS_SETUP_RESPONSE:
        /* only one TDLS link is supported */
        if ((status_code == 0) &&
            (rwnx_vif->sta.tdls_sta) &&
            (rwnx_vif->tdls_status == TDLS_LINK_ACTIVE)) {
            printk("%s: only one TDLS link is supported!\n", __func__);
            status_code = WLAN_STATUS_REQUEST_DECLINED;
        }
        /* fall-through */
    case WLAN_TDLS_SETUP_REQUEST:
    case WLAN_TDLS_TEARDOWN:
    case WLAN_TDLS_DISCOVERY_REQUEST:
    case WLAN_TDLS_SETUP_CONFIRM:
    case WLAN_PUB_ACTION_TDLS_DISCOVER_RES:
        ret = rwnx_tdls_send_mgmt_packet_data(rwnx_hw, rwnx_vif, peer, action_code,
                dialog_token, status_code, peer_capability, initiator, buf, len, 0, NULL);
        break;

    default:
        printk("%s: Unknown TDLS mgmt/action frame %pM\n",
                __func__, peer);
        ret = -EOPNOTSUPP;
        break;
    }

    if (action_code == WLAN_TDLS_SETUP_REQUEST) {
        rwnx_vif->tdls_status = TDLS_SETUP_REQ_TX;
    } else if (action_code == WLAN_TDLS_SETUP_RESPONSE) {
        rwnx_vif->tdls_status = TDLS_SETUP_RSP_TX;
    } else if ((action_code == WLAN_TDLS_SETUP_CONFIRM) && (ret == CO_OK)) {
        rwnx_vif->tdls_status = TDLS_LINK_ACTIVE;
        /* Set TDLS active */
        rwnx_vif->sta.tdls_sta->tdls.active = true;
    }

    return ret;
}

/**
 * @tdls_oper: Perform a high-level TDLS operation (e.g. TDLS link setup).
 */
static int rwnx_cfg80211_tdls_oper(struct wiphy *wiphy, struct net_device *dev,
                                   const u8 *peer, enum nl80211_tdls_operation oper)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    int error;

    if (oper != NL80211_TDLS_DISABLE_LINK)
        return 0;

    if (!rwnx_vif->sta.tdls_sta) {
        printk("%s: TDLS station %pM does not exist\n", __func__, peer);
        return -ENOLINK;
    }

    if (memcmp(rwnx_vif->sta.tdls_sta->mac_addr, peer, ETH_ALEN) == 0) {
        /* Disable Channel Switch */
        if (!rwnx_send_tdls_cancel_chan_switch_req(rwnx_hw, rwnx_vif,
                                                   rwnx_vif->sta.tdls_sta,
                                                   NULL))
            rwnx_vif->sta.tdls_sta->tdls.chsw_en = false;

        netdev_info(dev, "Del TDLS sta %d (%pM)",
                rwnx_vif->sta.tdls_sta->sta_idx,
                rwnx_vif->sta.tdls_sta->mac_addr);
        /* Ensure that we won't process PS change ind */
        spin_lock_bh(&rwnx_hw->cb_lock);
        rwnx_vif->sta.tdls_sta->ps.active = false;
        rwnx_vif->sta.tdls_sta->valid = false;
        spin_unlock_bh(&rwnx_hw->cb_lock);
        rwnx_txq_sta_deinit(rwnx_hw, rwnx_vif->sta.tdls_sta);
        error = rwnx_send_me_sta_del(rwnx_hw, rwnx_vif->sta.tdls_sta->sta_idx, true);
        if ((error != 0) && (error != -EPIPE))
            return error;

#ifdef CONFIG_RWNX_BFMER
        // Disable Beamformer if supported
        rwnx_bfmer_report_del(rwnx_hw, rwnx_vif->sta.tdls_sta);
        rwnx_mu_group_sta_del(rwnx_hw, rwnx_vif->sta.tdls_sta);
#endif /* CONFIG_RWNX_BFMER */

        /* Set TDLS not active */
        rwnx_vif->sta.tdls_sta->tdls.active = false;
        rwnx_dbgfs_unregister_sta(rwnx_hw, rwnx_vif->sta.tdls_sta);
        // Remove TDLS station
        rwnx_vif->tdls_status = TDLS_LINK_IDLE;
        rwnx_vif->sta.tdls_sta = NULL;
    }

    return 0;
}

/**
 *  @tdls_channel_switch: Start channel-switching with a TDLS peer. The driver
 *	is responsible for continually initiating channel-switching operations
 *	and returning to the base channel for communication with the AP.
 */
static int rwnx_cfg80211_tdls_channel_switch(struct wiphy *wiphy,
                                             struct net_device *dev,
                                             const u8 *addr, u8 oper_class,
                                             struct cfg80211_chan_def *chandef)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_sta *rwnx_sta = rwnx_vif->sta.tdls_sta;
    struct tdls_chan_switch_cfm cfm;
    int error;

    if ((!rwnx_sta) || (memcmp(addr, rwnx_sta->mac_addr, ETH_ALEN))) {
        printk("%s: TDLS station %pM doesn't exist\n", __func__, addr);
        return -ENOLINK;
    }

    if (!rwnx_sta->tdls.chsw_allowed) {
        printk("%s: TDLS station %pM does not support TDLS channel switch\n", __func__, addr);
        return -ENOTSUPP;
    }

    error = rwnx_send_tdls_chan_switch_req(rwnx_hw, rwnx_vif, rwnx_sta,
                                           rwnx_sta->tdls.initiator,
                                           oper_class, chandef, &cfm);
    if (error)
        return error;

    if (!cfm.status) {
        rwnx_sta->tdls.chsw_en = true;
        return 0;
    } else {
        printk("%s: TDLS channel switch already enabled and only one is supported\n", __func__);
        return -EALREADY;
    }
}

/**
 * @tdls_cancel_channel_switch: Stop channel-switching with a TDLS peer. Both
 *	peers must be on the base channel when the call completes.
 */
static void rwnx_cfg80211_tdls_cancel_channel_switch(struct wiphy *wiphy,
                                                     struct net_device *dev,
                                                     const u8 *addr)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_sta *rwnx_sta = rwnx_vif->sta.tdls_sta;
    struct tdls_cancel_chan_switch_cfm cfm;

    if (!rwnx_sta)
        return;

    if (!rwnx_send_tdls_cancel_chan_switch_req(rwnx_hw, rwnx_vif,
                                               rwnx_sta, &cfm))
        rwnx_sta->tdls.chsw_en = false;
}

/**
 * @change_bss: Modify parameters for a given BSS (mainly for AP mode).
 */
static int rwnx_cfg80211_change_bss(struct wiphy *wiphy, struct net_device *dev,
                                    struct bss_parameters *params)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    int res =  -EOPNOTSUPP;

    if (((RWNX_VIF_TYPE(rwnx_vif) == NL80211_IFTYPE_AP) ||
         (RWNX_VIF_TYPE(rwnx_vif) == NL80211_IFTYPE_P2P_GO)) &&
        (params->ap_isolate > -1)) {

        if (params->ap_isolate)
            rwnx_vif->ap.flags |= RWNX_AP_ISOLATE;
        else
            rwnx_vif->ap.flags &= ~RWNX_AP_ISOLATE;

        res = 0;
    }

    return res;
}


static int rwnx_fill_station_info(struct rwnx_sta *sta, struct rwnx_vif *vif,
                                  struct station_info *sinfo)
{
    struct rwnx_sta_stats *stats = &sta->stats;
    struct rx_vector_1 *rx_vect1 = &stats->last_rx.rx_vect1;

    // Generic info
    sinfo->generation = vif->generation;

    sinfo->inactive_time = jiffies_to_msecs(jiffies - stats->last_act);
    sinfo->rx_bytes = stats->rx_bytes;
    sinfo->tx_bytes = stats->tx_bytes;
    sinfo->tx_packets = stats->tx_pkts;
    sinfo->rx_packets = stats->rx_pkts;
    sinfo->signal = rx_vect1->rssi1;
    sinfo->tx_failed = stats->tx_fails;
    switch (rx_vect1->ch_bw) {
        case PHY_CHNL_BW_20:
            sinfo->rxrate.bw = RATE_INFO_BW_20;
            break;
        case PHY_CHNL_BW_40:
            sinfo->rxrate.bw = RATE_INFO_BW_40;
            break;
        case PHY_CHNL_BW_80:
            sinfo->rxrate.bw = RATE_INFO_BW_80;
            break;
        case PHY_CHNL_BW_160:
            sinfo->rxrate.bw = RATE_INFO_BW_160;
            break;
        default:
            sinfo->rxrate.bw = RATE_INFO_BW_HE_RU;
            break;
    }
    switch (rx_vect1->format_mod) {
        case FORMATMOD_NON_HT:
        case FORMATMOD_NON_HT_DUP_OFDM:
            sinfo->rxrate.flags = 0;
            sinfo->rxrate.legacy = legrates_lut[rx_vect1->leg_rate].rate;
            break;
        case FORMATMOD_HT_MF:
        case FORMATMOD_HT_GF:
            sinfo->rxrate.flags = RATE_INFO_FLAGS_MCS;
            if (rx_vect1->ht.short_gi)
                sinfo->rxrate.flags |= RATE_INFO_FLAGS_SHORT_GI;
            sinfo->rxrate.mcs = rx_vect1->ht.mcs;
            break;
        case FORMATMOD_VHT:
            sinfo->rxrate.flags = RATE_INFO_FLAGS_VHT_MCS;
            if (rx_vect1->vht.short_gi)
                sinfo->rxrate.flags |= RATE_INFO_FLAGS_SHORT_GI;
            sinfo->rxrate.mcs = rx_vect1->vht.mcs;
            sinfo->rxrate.nss = rx_vect1->vht.nss + 1;
            break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
        case FORMATMOD_HE_MU:
            sinfo->rxrate.he_ru_alloc = rx_vect1->he.ru_size;
        case FORMATMOD_HE_SU:
        case FORMATMOD_HE_ER:
        case FORMATMOD_HE_TB:
            sinfo->rxrate.flags = RATE_INFO_FLAGS_HE_MCS;
            sinfo->rxrate.mcs = rx_vect1->he.mcs;
            sinfo->rxrate.nss = rx_vect1->he.nss + 1;
            sinfo->rxrate.he_gi = rx_vect1->he.gi_type;
            sinfo->rxrate.he_dcm = rx_vect1->he.dcm;
            break;
#endif
        default :
            return -EINVAL;
    }
    sinfo->filled = (BIT(NL80211_STA_INFO_INACTIVE_TIME) |
                     BIT(NL80211_STA_INFO_RX_BYTES64)    |
                     BIT(NL80211_STA_INFO_TX_BYTES64)    |
                     BIT(NL80211_STA_INFO_RX_PACKETS)    |
                     BIT(NL80211_STA_INFO_TX_PACKETS)    |
                     BIT(NL80211_STA_INFO_TX_FAILED)     |
                     BIT(NL80211_STA_INFO_SIGNAL)        |
                     BIT(NL80211_STA_INFO_RX_BITRATE));


    switch (stats->bw_max) {
        case PHY_CHNL_BW_20:
            sinfo->txrate.bw = RATE_INFO_BW_20;
            break;
        case PHY_CHNL_BW_40:
            sinfo->txrate.bw = RATE_INFO_BW_40;
            break;
        case PHY_CHNL_BW_80:
            sinfo->txrate.bw = RATE_INFO_BW_80;
            break;
        case PHY_CHNL_BW_160:
            sinfo->txrate.bw = RATE_INFO_BW_160;
            break;
        default:
            sinfo->txrate.bw = RATE_INFO_BW_HE_RU;
            break;
    }
     switch (stats->format_mod) {
        case FORMATMOD_NON_HT:
        case FORMATMOD_NON_HT_DUP_OFDM:
            sinfo->txrate.flags = 0;
            sinfo->txrate.legacy = stats->leg_rate;
            break;
        case FORMATMOD_HT_MF:
        case FORMATMOD_HT_GF:
            sinfo->txrate.flags = RATE_INFO_FLAGS_MCS;
            if (stats->short_gi)
                sinfo->txrate.flags |= RATE_INFO_FLAGS_SHORT_GI;
            sinfo->txrate.mcs = stats->mcs_max;
            break;
        case FORMATMOD_VHT:
            sinfo->txrate.flags = RATE_INFO_FLAGS_VHT_MCS;
            if (stats->short_gi)
                sinfo->txrate.flags |= RATE_INFO_FLAGS_SHORT_GI;
            sinfo->txrate.mcs = stats->mcs_max;
            sinfo->txrate.nss = stats->no_ss + 1;
            break;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0)
        case FORMATMOD_HE_MU:
        case FORMATMOD_HE_SU:
        case FORMATMOD_HE_ER:
        case FORMATMOD_HE_TB:
            sinfo->txrate.flags = RATE_INFO_FLAGS_HE_MCS;
            sinfo->txrate.mcs = stats->mcs_max;
            sinfo->txrate.nss = stats->no_ss + 1;
            break;
#endif
        default :
            return -EINVAL;
    }
    sinfo->filled |= BIT(NL80211_STA_INFO_TX_BITRATE);

    sinfo->bss_param.flags = 0;
    //sinfo->bss_param.dtim_period = stats->dtim; TODO:need to add later
    sinfo->bss_param.beacon_interval = stats->bcn_interval / 1024;

    sinfo->filled |= BIT(NL80211_STA_INFO_BSS_PARAM);
    // Mesh specific info
    if (RWNX_VIF_TYPE(vif) == NL80211_IFTYPE_MESH_POINT)
    {
        struct mesh_peer_info_cfm peer_info_cfm;
        if (rwnx_send_mesh_peer_info_req(vif->rwnx_hw, vif, sta->sta_idx,
                                         &peer_info_cfm))
            return -ENOMEM;

        peer_info_cfm.last_bcn_age = peer_info_cfm.last_bcn_age / 1000;
        if (peer_info_cfm.last_bcn_age < sinfo->inactive_time)
            sinfo->inactive_time = peer_info_cfm.last_bcn_age;

        sinfo->llid = peer_info_cfm.local_link_id;
        sinfo->plid = peer_info_cfm.peer_link_id;
        sinfo->plink_state = peer_info_cfm.link_state;
        sinfo->local_pm = (enum nl80211_mesh_power_mode)peer_info_cfm.local_ps_mode;
        sinfo->peer_pm = (enum nl80211_mesh_power_mode)peer_info_cfm.peer_ps_mode;
        sinfo->nonpeer_pm = (enum nl80211_mesh_power_mode)peer_info_cfm.non_peer_ps_mode;

        sinfo->filled |= (BIT(NL80211_STA_INFO_LLID) |
                          BIT(NL80211_STA_INFO_PLID) |
                          BIT(NL80211_STA_INFO_PLINK_STATE) |
                          BIT(NL80211_STA_INFO_LOCAL_PM) |
                          BIT(NL80211_STA_INFO_PEER_PM) |
                          BIT(NL80211_STA_INFO_NONPEER_PM));
    }

    return 0;
}

/**
 * @get_station: get station information for the station identified by @mac
 */
static int rwnx_cfg80211_get_station(struct wiphy *wiphy, struct net_device *dev,
                                     const u8 *mac, struct station_info *sinfo)
{
    struct rwnx_vif *vif = netdev_priv(dev);
    struct rwnx_sta *sta = NULL;
    if (RWNX_VIF_TYPE(vif) == NL80211_IFTYPE_MONITOR)
        return -EINVAL;
    else if ((RWNX_VIF_TYPE(vif) == NL80211_IFTYPE_STATION) ||
             (RWNX_VIF_TYPE(vif) == NL80211_IFTYPE_P2P_CLIENT)) {
        if (vif->sta.ap && ether_addr_equal(vif->sta.ap->mac_addr, mac))
            sta = vif->sta.ap;
    }
    else
    {
        struct rwnx_sta *sta_iter;
        list_for_each_entry(sta_iter, &vif->ap.sta_list, list) {
            if (sta_iter->valid && ether_addr_equal(sta_iter->mac_addr, mac)) {
                sta = sta_iter;
                break;
            }
        }
    }
    if (sta)
        return rwnx_fill_station_info(sta, vif, sinfo);
    return -EINVAL;
}

/**
 * @dump_station: dump station callback -- resume dump at index @idx
 */
static int rwnx_cfg80211_dump_station(struct wiphy *wiphy, struct net_device *dev,
                                      int idx, u8 *mac, struct station_info *sinfo)
{
    struct rwnx_vif *vif = netdev_priv(dev);
    struct rwnx_sta *sta = NULL;

    if (RWNX_VIF_TYPE(vif) == NL80211_IFTYPE_MONITOR)
        return -EINVAL;
    else if ((RWNX_VIF_TYPE(vif) == NL80211_IFTYPE_STATION) ||
             (RWNX_VIF_TYPE(vif) == NL80211_IFTYPE_P2P_CLIENT)) {
        if ((idx == 0) && vif->sta.ap && vif->sta.ap->valid)
            sta = vif->sta.ap;
    } else {
        struct rwnx_sta *sta_iter;
        int i = 0;
        list_for_each_entry(sta_iter, &vif->ap.sta_list, list) {
            if (i == idx) {
                sta = sta_iter;
                break;
            }
            i++;
        }
    }

    if (sta == NULL)
        return -ENOENT;

    /* Copy peer MAC address */
    memcpy(mac, &sta->mac_addr, ETH_ALEN);

    return rwnx_fill_station_info(sta, vif, sinfo);
}

/**
 * @add_mpath: add a fixed mesh path
 */
static int rwnx_cfg80211_add_mpath(struct wiphy *wiphy, struct net_device *dev,
                                   const u8 *dst, const u8 *next_hop)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct mesh_path_update_cfm cfm;

    if (RWNX_VIF_TYPE(rwnx_vif) != NL80211_IFTYPE_MESH_POINT)
        return -ENOTSUPP;

    return rwnx_send_mesh_path_update_req(rwnx_hw, rwnx_vif, dst, next_hop, &cfm);
}

/**
 * @del_mpath: delete a given mesh path
 */
static int rwnx_cfg80211_del_mpath(struct wiphy *wiphy, struct net_device *dev,
                                   const u8 *dst)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct mesh_path_update_cfm cfm;

    if (RWNX_VIF_TYPE(rwnx_vif) != NL80211_IFTYPE_MESH_POINT)
        return -ENOTSUPP;

    return rwnx_send_mesh_path_update_req(rwnx_hw, rwnx_vif, dst, NULL, &cfm);
}

/**
 * @change_mpath: change a given mesh path
 */
static int rwnx_cfg80211_change_mpath(struct wiphy *wiphy, struct net_device *dev,
                                      const u8 *dst, const u8 *next_hop)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct mesh_path_update_cfm cfm;

    if (RWNX_VIF_TYPE(rwnx_vif) != NL80211_IFTYPE_MESH_POINT)
        return -ENOTSUPP;

    return rwnx_send_mesh_path_update_req(rwnx_hw, rwnx_vif, dst, next_hop, &cfm);
}

/**
 * @get_mpath: get a mesh path for the given parameters
 */
static int rwnx_cfg80211_get_mpath(struct wiphy *wiphy, struct net_device *dev,
                                   u8 *dst, u8 *next_hop, struct mpath_info *pinfo)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct rwnx_mesh_path *mesh_path = NULL;
    struct rwnx_mesh_path *cur;

    if (RWNX_VIF_TYPE(rwnx_vif) != NL80211_IFTYPE_MESH_POINT)
        return -ENOTSUPP;

    list_for_each_entry(cur, &rwnx_vif->ap.mpath_list, list) {
        /* Compare the path target address and the provided destination address */
        if (memcmp(dst, &cur->tgt_mac_addr, ETH_ALEN)) {
            continue;
        }

        mesh_path = cur;
        break;
    }

    if (mesh_path == NULL)
        return -ENOENT;

    /* Copy next HOP MAC address */
    if (mesh_path->nhop_sta)
        memcpy(next_hop, &mesh_path->nhop_sta->mac_addr, ETH_ALEN);

    /* Fill path information */
    pinfo->filled = 0;
    pinfo->generation = rwnx_vif->generation;

    return 0;
}

/**
 * @dump_mpath: dump mesh path callback -- resume dump at index @idx
 */
static int rwnx_cfg80211_dump_mpath(struct wiphy *wiphy, struct net_device *dev,
                                    int idx, u8 *dst, u8 *next_hop,
                                    struct mpath_info *pinfo)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct rwnx_mesh_path *mesh_path = NULL;
    struct rwnx_mesh_path *cur;
    int i = 0;

    if (RWNX_VIF_TYPE(rwnx_vif) != NL80211_IFTYPE_MESH_POINT)
        return -ENOTSUPP;

    list_for_each_entry(cur, &rwnx_vif->ap.mpath_list, list) {
        if (i < idx) {
            i++;
            continue;
        }

        mesh_path = cur;
        break;
    }

    if (mesh_path == NULL)
        return -ENOENT;

    /* Copy target and next hop MAC address */
    memcpy(dst, &mesh_path->tgt_mac_addr, ETH_ALEN);
    if (mesh_path->nhop_sta)
        memcpy(next_hop, &mesh_path->nhop_sta->mac_addr, ETH_ALEN);

    /* Fill path information */
    pinfo->filled = 0;
    pinfo->generation = rwnx_vif->generation;

    return 0;
}

/**
 * @get_mpp: get a mesh proxy path for the given parameters
 */
static int rwnx_cfg80211_get_mpp(struct wiphy *wiphy, struct net_device *dev,
                                 u8 *dst, u8 *mpp, struct mpath_info *pinfo)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct rwnx_mesh_proxy *mesh_proxy = NULL;
    struct rwnx_mesh_proxy *cur;

    if (RWNX_VIF_TYPE(rwnx_vif) != NL80211_IFTYPE_MESH_POINT)
        return -ENOTSUPP;

    list_for_each_entry(cur, &rwnx_vif->ap.proxy_list, list) {
        if (cur->local) {
            continue;
        }

        /* Compare the path target address and the provided destination address */
        if (memcmp(dst, &cur->ext_sta_addr, ETH_ALEN)) {
            continue;
        }

        mesh_proxy = cur;
        break;
    }

    if (mesh_proxy == NULL)
        return -ENOENT;

    memcpy(mpp, &mesh_proxy->proxy_addr, ETH_ALEN);

    /* Fill path information */
    pinfo->filled = 0;
    pinfo->generation = rwnx_vif->generation;

    return 0;
}

/**
 * @dump_mpp: dump mesh proxy path callback -- resume dump at index @idx
 */
static int rwnx_cfg80211_dump_mpp(struct wiphy *wiphy, struct net_device *dev,
                                  int idx, u8 *dst, u8 *mpp, struct mpath_info *pinfo)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct rwnx_mesh_proxy *mesh_proxy = NULL;
    struct rwnx_mesh_proxy *cur;
    int i = 0;

    if (RWNX_VIF_TYPE(rwnx_vif) != NL80211_IFTYPE_MESH_POINT)
        return -ENOTSUPP;

    list_for_each_entry(cur, &rwnx_vif->ap.proxy_list, list) {
        if (cur->local) {
            continue;
        }

        if (i < idx) {
            i++;
            continue;
        }

        mesh_proxy = cur;
        break;
    }

    if (mesh_proxy == NULL)
        return -ENOENT;

    /* Copy target MAC address */
    memcpy(dst, &mesh_proxy->ext_sta_addr, ETH_ALEN);
    memcpy(mpp, &mesh_proxy->proxy_addr, ETH_ALEN);

    /* Fill path information */
    pinfo->filled = 0;
    pinfo->generation = rwnx_vif->generation;

    return 0;
}

/**
 * @get_mesh_config: Get the current mesh configuration
 */
static int rwnx_cfg80211_get_mesh_config(struct wiphy *wiphy, struct net_device *dev,
                                         struct mesh_config *conf)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);

    if (RWNX_VIF_TYPE(rwnx_vif) != NL80211_IFTYPE_MESH_POINT)
        return -ENOTSUPP;

    return 0;
}

/**
 * @update_mesh_config: Update mesh parameters on a running mesh.
 */
static int rwnx_cfg80211_update_mesh_config(struct wiphy *wiphy, struct net_device *dev,
                                            u32 mask, const struct mesh_config *nconf)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct mesh_update_cfm cfm;
    int status;

    if (RWNX_VIF_TYPE(rwnx_vif) != NL80211_IFTYPE_MESH_POINT)
        return -ENOTSUPP;

    if (mask & CO_BIT(NL80211_MESHCONF_POWER_MODE - 1)) {
        rwnx_vif->ap.next_mesh_pm = nconf->power_mode;

        if (!list_empty(&rwnx_vif->ap.sta_list)) {
            // If there are mesh links we don't want to update the power mode
            // It will be updated with rwnx_update_mesh_power_mode() when the
            // ps mode of a link is updated or when a new link is added/removed
            mask &= ~BIT(NL80211_MESHCONF_POWER_MODE - 1);

            if (!mask)
                return 0;
        }
    }

    status = rwnx_send_mesh_update_req(rwnx_hw, rwnx_vif, mask, nconf, &cfm);

    if (!status && (cfm.status != 0))
        status = -EINVAL;

    return status;
}

/**
 * @join_mesh: join the mesh network with the specified parameters
 * (invoked with the wireless_dev mutex held)
 */
static int rwnx_cfg80211_join_mesh(struct wiphy *wiphy, struct net_device *dev,
                                   const struct mesh_config *conf, const struct mesh_setup *setup)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct mesh_start_cfm mesh_start_cfm;
    int error = 0;
    u8 txq_status = 0;
    /* STA for BC/MC traffic */
    struct rwnx_sta *sta;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    if (RWNX_VIF_TYPE(rwnx_vif) != NL80211_IFTYPE_MESH_POINT)
        return -ENOTSUPP;

    /* Forward the information to the UMAC */
    if ((error = rwnx_send_mesh_start_req(rwnx_hw, rwnx_vif, conf, setup, &mesh_start_cfm))) {
        return error;
    }

    /* Check the status */
    switch (mesh_start_cfm.status) {
        case CO_OK:
            rwnx_vif->ap.bcmc_index = mesh_start_cfm.bcmc_idx;
            rwnx_vif->ap.flags = 0;
            rwnx_vif->ap.bcn_interval = setup->beacon_interval;
            rwnx_vif->use_4addr = true;
            if (setup->user_mpm)
                rwnx_vif->ap.flags |= RWNX_AP_USER_MESH_PM;

            sta = &rwnx_hw->sta_table[mesh_start_cfm.bcmc_idx];
            sta->valid = true;
            sta->aid = 0;
            sta->sta_idx = mesh_start_cfm.bcmc_idx;
            sta->ch_idx = mesh_start_cfm.ch_idx;
            sta->vif_idx = rwnx_vif->vif_index;
            sta->qos = true;
            sta->acm = 0;
            sta->ps.active = false;
            sta->listen_interval = 5;
            rwnx_mu_group_sta_init(sta, NULL);
            spin_lock_bh(&rwnx_hw->cb_lock);
            rwnx_chanctx_link(rwnx_vif, mesh_start_cfm.ch_idx,
                              (struct cfg80211_chan_def *)(&setup->chandef));
            if (rwnx_hw->cur_chanctx != mesh_start_cfm.ch_idx) {
                txq_status = RWNX_TXQ_STOP_CHAN;
            }
            rwnx_txq_vif_init(rwnx_hw, rwnx_vif, txq_status);
            spin_unlock_bh(&rwnx_hw->cb_lock);

            netif_tx_start_all_queues(dev);
            netif_carrier_on(dev);

            /* If the AP channel is already the active, we probably skip radar
               activation on MM_CHANNEL_SWITCH_IND (unless another vif use this
               ctxt). In anycase retest if radar detection must be activated
             */
            if (rwnx_hw->cur_chanctx == mesh_start_cfm.ch_idx) {
                rwnx_radar_detection_enable_on_cur_channel(rwnx_hw);
            }
            break;

        case CO_BUSY:
            error = -EINPROGRESS;
            break;

        default:
            error = -EIO;
            break;
    }

    /* Print information about the operation */
    if (error) {
        netdev_info(dev, "Failed to start MP (%d)", error);
    } else {
        netdev_info(dev, "MP started: ch=%d, bcmc_idx=%d",
                    rwnx_vif->ch_index, rwnx_vif->ap.bcmc_index);
    }

    return error;
}

/**
 * @leave_mesh: leave the current mesh network
 * (invoked with the wireless_dev mutex held)
 */
static int rwnx_cfg80211_leave_mesh(struct wiphy *wiphy, struct net_device *dev)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);
    struct mesh_stop_cfm mesh_stop_cfm;
    int error = 0;

    error = rwnx_send_mesh_stop_req(rwnx_hw, rwnx_vif, &mesh_stop_cfm);

    if (error == 0) {
        /* Check the status */
        switch (mesh_stop_cfm.status) {
            case CO_OK:
                spin_lock_bh(&rwnx_hw->cb_lock);
                rwnx_chanctx_unlink(rwnx_vif);
                rwnx_radar_cancel_cac(&rwnx_hw->radar);
                spin_unlock_bh(&rwnx_hw->cb_lock);
                /* delete BC/MC STA */
                rwnx_txq_vif_deinit(rwnx_hw, rwnx_vif);
                rwnx_del_bcn(&rwnx_vif->ap.bcn);

                netif_tx_stop_all_queues(dev);
                netif_carrier_off(dev);

                break;

            default:
                error = -EIO;
                break;
        }
    }

    if (error) {
        netdev_info(dev, "Failed to stop MP");
    } else {
        netdev_info(dev, "MP Stopped");
    }

    return 0;
}

#ifdef CONFIG_RWNX_SUSPEND
int rwnx_pwrsave_wow_sta(struct rwnx_hw *rwnx_hw, struct rwnx_vif *rwnx_vif)
{
    /*
    * bitmask where to match pattern and where to ignore
    * bytes, one bit per byte
    */
    int error = 0;
    unsigned char mask = 0x3f;
    struct cfg80211_pkt_pattern pattern;

    memset(&pattern, 0, sizeof(pattern));
    pattern.mask = (u8 *)&mask;
    pattern.pattern_len = ETH_ALEN;
    pattern.pkt_offset = 0;
    pattern.pattern = rwnx_vif->ndev->dev_addr;

    if ((error = rwnx_send_wow_pattern(rwnx_hw, rwnx_vif, &pattern, 0)))
        return error;

    return 0;
}


int rwnx_pwrsave_wow_usr(struct rwnx_hw *rwnx_hw, struct rwnx_vif *rwnx_vif,
    struct cfg80211_wowlan *wow, unsigned int *filter)
{
    int i, error;

    /*
    * Configure the patterns that we received from the user.
    * And we save WOW_MAX_FILTERS patterns at most.
    */
    for (i = 0; i < wow->n_patterns; i++){
        if ((error = rwnx_send_wow_pattern(rwnx_hw, rwnx_vif, &wow->patterns[i], i)))
            return error;
    }

    /* pno offload*/
    if (wow->nd_config) {
        rwnx_send_sched_scan_req(rwnx_vif, wow->nd_config);
    }

    /*get wakeup filter */
    if (wow->disconnect)
        *filter |= WOW_FILTER_OPTION_DISCONNECT;

    if (wow->magic_pkt)
        *filter |= WOW_FILTER_OPTION_MAGIC_PACKET;

    if (wow->gtk_rekey_failure)
        *filter |= WOW_FILTER_OPTION_GTK_ERROR;

    if (wow->eap_identity_req)
        *filter |= WOW_FILTER_OPTION_EAP_REQ;

    if (wow->four_way_handshake)
        *filter |= WOW_FILTER_OPTION_4WAYHS;

    return 0;
}

int rwnx_cancel_scan(struct rwnx_hw *rwnx_hw, struct rwnx_vif *vif)
{
    struct scanu_cancel_cfm scanu_cancel_cfm;
    int error = 0, cnt = 0;

    vif->sta.scan_hang = 1;
    if ((error = rwnx_send_scanu_cancel_req(rwnx_hw, vif, &scanu_cancel_cfm))) {
        return error;
    }
    while (!vif->sta.cancel_scan_cfm) {
        msleep(20);
        if (cnt++ > 20) {
            return -EINVAL;
        }
    }

    return 0;
}

static int rwnx_set_arp_agent(struct rwnx_hw *rwnx_hw, struct rwnx_vif *rwnx_vif, u8 enable)
{
    struct in_device *in_dev;
    struct in_ifaddr *ifa_v4;
    struct inet6_dev *idev_v6 = NULL;
    struct inet6_ifaddr *ifa_v6 = NULL;
    struct in6_addr *ipv6_ptr = NULL;
    __be32 ipv4;

    unsigned char ipv6[IPV6_ADDR_BUF_LEN] = {0};
    int i = 0, j = 0;

    if (enable == 0) {
        /*just disable arp agent */
        return rwnx_send_arp_agent_req(rwnx_hw, rwnx_vif, enable, 0, NULL);
    }
    /* get ipv4 addr */
    in_dev = __in_dev_get_rtnl(rwnx_vif->ndev);
    if (!in_dev)
        return -EINVAL;

    ifa_v4 = in_dev->ifa_list;
    if (!ifa_v4) {
        return -EINVAL;
    }
    memset(&ipv4, 0, sizeof(ipv4));
    ipv4 = ifa_v4->ifa_local;

    /*get ipv6 addr */
    idev_v6 = __in6_dev_get(rwnx_vif->ndev);
    if (!idev_v6) {
        printk("not support ipv6\n");
        return -EINVAL;
    }

    read_lock_bh(&idev_v6->lock);
    list_for_each_entry(ifa_v6, &idev_v6->addr_list, if_list) {
        unsigned int addr_type = __ipv6_addr_type(&ifa_v6->addr);

        if ((ifa_v6->flags & IFA_F_TENTATIVE) &&
              (!(ifa_v6->flags & IFA_F_OPTIMISTIC)))
            continue;

        if (unlikely(addr_type == IPV6_ADDR_ANY ||
                     addr_type & IPV6_ADDR_MULTICAST))
            continue;

        ipv6_ptr = &ifa_v6->addr;
        if (ipv6_ptr->in6_u.u6_addr8[0] != 0) {
            memcpy(ipv6 + j * sizeof(struct in6_addr), ipv6_ptr->in6_u.u6_addr8, sizeof(struct in6_addr));
            j++;
        }
        i++;
        /* we just support 3 ipv6 addr at most. */
        if (i > 2)
            break;
    }
    read_unlock_bh(&idev_v6->lock);

    return rwnx_send_arp_agent_req(rwnx_hw, rwnx_vif, enable, ipv4, ipv6);
}

static int rwnx_ps_wow_resume(struct rwnx_hw *rwnx_hw)
{
    struct rwnx_vif *rwnx_vif;
    int error = 0;

    RWNX_DBG(RWNX_FN_ENTRY_STR);
    if (rwnx_hw->state == WIFI_SUSPEND_STATE_NONE) {
        return -EINVAL;
    }

    list_for_each_entry(rwnx_vif, &rwnx_hw->vifs, list) {
        if (!rwnx_vif->up || rwnx_vif->ndev == NULL) {
            continue;
        }

        if (RWNX_VIF_TYPE(rwnx_vif) == NL80211_IFTYPE_STATION) {
            break;
        }
    }

    if (rwnx_vif != NULL) {
        error = rwnx_send_suspend_req(rwnx_hw, rwnx_vif, WIFI_SUSPEND_STATE_NONE);
        if (error) {
            return error;
        }

        netif_start_queue(rwnx_vif->ndev);

        rwnx_hw->state = WIFI_SUSPEND_STATE_NONE;

        if (rwnx_vif->sta.ap && rwnx_vif->sta.ap->valid) {
            rwnx_txq_vif_start(rwnx_vif, RWNX_TXQ_STOP, rwnx_hw);
            rwnx_vif->filter = 0;
            rwnx_set_arp_agent(rwnx_hw, rwnx_vif, 0);
            rwnx_tko_activate(rwnx_hw, rwnx_vif, 0);
        }

        netif_wake_queue(rwnx_vif->ndev);

        aml_scan_hang(rwnx_vif, 0);
        rwnx_vif->sta.scan_hang = 0;
    } else {
        printk("no sta interface, do nothing now\n");
    }

    return 0;
}

static int rwnx_ps_wow_suspend(struct rwnx_hw *rwnx_hw, struct cfg80211_wowlan *wow)
{
    struct rwnx_vif *rwnx_vif;
    int error = 0;
    unsigned int filter = 0;
    int count = 0;

    RWNX_DBG(RWNX_FN_ENTRY_STR);
    if (rwnx_hw->state == WIFI_SUSPEND_STATE_WOW) {
        return -EINVAL;
    }

    //only support suspend under sta interface.
    list_for_each_entry(rwnx_vif, &rwnx_hw->vifs, list) {
        if (!rwnx_vif->up || rwnx_vif->ndev == NULL) {
            continue;
        }

        if (RWNX_VIF_TYPE(rwnx_vif) == NL80211_IFTYPE_STATION) {
            break;
        }
    }

    if (rwnx_vif != NULL) {
        netif_stop_queue(rwnx_vif->ndev);

        if (rwnx_vif->sta.ap && rwnx_vif->sta.ap->valid) {
            rwnx_txq_vif_stop(rwnx_vif, RWNX_TXQ_STOP, rwnx_hw);
            rwnx_set_arp_agent(rwnx_hw, rwnx_vif, 1);
            rwnx_tko_activate(rwnx_hw, rwnx_vif, 1);

            if (wow != NULL) {
                rwnx_pwrsave_wow_usr(rwnx_hw, rwnx_vif, wow, &filter);

            } else {
                rwnx_pwrsave_wow_sta(rwnx_hw, rwnx_vif);
            }
            rwnx_vif->filter = filter;

            while (!rwnx_txq_is_empty(rwnx_hw, rwnx_vif->sta.ap)) {
                msleep(10);

                if(count++ > 10) {
                     return -EINVAL;
                }
           }
        }

//        rwnx_send_me_set_ps_mode(rwnx_hw, MM_PS_MODE_ON_DYN);
        rwnx_hw->state = WIFI_SUSPEND_STATE_WOW;

        printk("before cancel scan:%d\n", rwnx_hw->cmd_mgr.queue_sz);
        error = rwnx_cancel_scan(rwnx_hw, rwnx_vif);
        if (error) {
            return error;
        }

        //last cmd before suspend
        error = rwnx_send_suspend_req(rwnx_hw, rwnx_vif, WIFI_SUSPEND_STATE_WOW);
        if (error) {
            return error;
        }
        printk("after suspend cmd:%d\n", rwnx_hw->cmd_mgr.queue_sz);

    } else {
        printk("no sta interface, do nothing now\n");
    }

    return 0;
}
#endif

static int rwnx_cfg80211_suspend(struct wiphy *wiphy, struct cfg80211_wowlan *wow)
{
#ifdef CONFIG_RWNX_SUSPEND
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    int error = 0;

    if (wow && (wow->n_patterns > WOW_MAX_PATTERNS))
        return -EINVAL;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    error = rwnx_ps_wow_suspend(rwnx_hw, wow);
    if (error){
        return error;
    }
    return 0;
#else
    printk("test %s,%d, suspend is not supported\n", __func__, __LINE__);
    return 0;
#endif
}

static int rwnx_cfg80211_resume(struct wiphy *wiphy)
{
#ifdef CONFIG_RWNX_SUSPEND
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);
    int error = 0;

    RWNX_DBG(RWNX_FN_ENTRY_STR);
    error = rwnx_ps_wow_resume(rwnx_hw);
    if (error){
        return error;
    }
    return 0;
#else
    printk("%s,%d, resume is not supported\n", __func__, __LINE__);
    return 0;
#endif
}

static int rwnx_cfg80211_set_rekey_data(struct wiphy *wiphy,
    struct net_device *dev,struct cfg80211_gtk_rekey_data *data)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);

    if (RWNX_VIF_TYPE(rwnx_vif) ==  NL80211_IFTYPE_STATION) {
        rwnx_set_rekey_data(rwnx_vif, data->kek, data->kck, data->replay_ctr);
        return 0;
    }

    return -1;
}

unsigned char rwnx_get_s8_item(char *varbuf, int len, char *item, char *item_value)
{
    unsigned int n;
    char tmpbuf[20];
    char *p = item_value;
    int ret = 0;
    unsigned int pos = 0;
    unsigned int index = 0;

    while (pos  < len) {
        index = pos;
        ret = 0;

        while ((varbuf[pos] != 0) && (varbuf[pos] != '=')) {
            if (((pos - index) >= strlen(item)) || (varbuf[pos] != item[pos - index])) {
                ret = 1;
                break;
            }
            else {
                pos++;
            }
        }

        pos++;

        if ((ret == 0) && (strlen(item) == pos - index - 1)) {
            do {
                memset(tmpbuf, 0, sizeof(tmpbuf));
                n = 0;
                while ((varbuf[pos] != 0) && (varbuf[pos] != ',') && (pos < len))
                    tmpbuf[n++] = varbuf[pos++];

                *p++ = (char)simple_strtol(tmpbuf, NULL, 0);
            }
            while (varbuf[pos++] == ',');

            return 0;
        }
    }

    return 1;
}

unsigned char rwnx_get_s16_item(char *varbuf, int len, char *item, short *item_value)
{
    unsigned int n;
    char tmpbuf[60];
    short *p = item_value;
    int ret = 0;
    unsigned int pos = 0;
    unsigned int index = 0;

    while (pos  < len) {
        index = pos;
        ret = 0;

        while ((varbuf[pos] != 0) && (varbuf[pos] != '=')) {
            if (((pos - index) >= strlen(item)) || (varbuf[pos] != item[pos - index])) {
                ret = 1;
                break;
            }
            else {
                pos++;
            }
        }

        pos++;

        if ((ret == 0) && (strlen(item) == pos - index - 1)) {
            do {
                memset(tmpbuf, 0, sizeof(tmpbuf));
                n = 0;
                while ((varbuf[pos] != 0) && (varbuf[pos] != ',') && (pos < len))
                    tmpbuf[n++] = varbuf[pos++];

                *p++ = (short)simple_strtol(tmpbuf, NULL, 0);
            }
            while (varbuf[pos++] == ',');

            return 0;
        }
    }

    return 1;
}

unsigned char rwnx_get_s32_item(char *varbuf, int len, char *item, unsigned int *item_value)
{
    unsigned int n;
    char tmpbuf[120];
    unsigned int *p = item_value;
    int ret = 0;
    unsigned int pos = 0;
    unsigned int index = 0;

    while (pos  < len) {
        index = pos;
        ret = 0;

        while ((varbuf[pos] != 0) && (varbuf[pos] != '=')) {
            if (((pos - index) >= strlen(item)) || (varbuf[pos] != item[pos - index])) {
                ret = 1;
                break;
            }
            else {
                pos++;
            }
        }

        pos++;

        if ((ret == 0) && (strlen(item) == pos - index - 1)) {
            do {
                memset(tmpbuf, 0, sizeof(tmpbuf));
                n = 0;
                while ((varbuf[pos] != 0) && (varbuf[pos] != ',') && (pos < len))
                    tmpbuf[n++] = varbuf[pos++];

                *p++ = (unsigned int)simple_strtol(tmpbuf, NULL, 0);
            }
            while (varbuf[pos++] == ',');

            return 0;
        }
    }

    return 1;
}

unsigned int rwnx_process_cali_content(char *varbuf, unsigned int len)
{
    char *dp;
    bool findNewline;
    int column;
    unsigned int buf_len, n;
    unsigned int pad = 0;

    dp = varbuf;
    findNewline = false;
    column = 0;

    for (n = 0; n < len; n++) {
        if (varbuf[n] == '\r')
            continue;

        if (findNewline && varbuf[n] != '\n')
            continue;
        findNewline = false;
        if (varbuf[n] == '#') {
            findNewline = true;
            continue;
        }
        if (varbuf[n] == '\n') {
            if (column == 0)
                continue;
            *dp++ = 0;
            column = 0;
            continue;
        }
        *dp++ = varbuf[n];
        column++;
    }
    buf_len = (unsigned int)(dp - varbuf);
    if (buf_len % 4) {
        pad = 4 - buf_len % 4;
        if (pad && (buf_len + pad <= len)) {
            buf_len += pad;
        }
    }

    while (dp < varbuf + n)
        *dp++ = 0;

    return buf_len;
}

unsigned char rwnx_parse_cali_param(char *varbuf, int len, struct Cali_Param *cali_param)
{
    //unsigned short platform_verid = 0; // default: 0
    unsigned short cali_config = 0;
    unsigned int version = 0;

    rwnx_get_s32_item(varbuf, len, "version", &version);
    rwnx_get_s16_item(varbuf, len, "cali_config", &cali_config);
    rwnx_get_s8_item(varbuf, len, "freq_offset", &cali_param->freq_offset);
    rwnx_get_s8_item(varbuf, len, "htemp_freq_offset", &cali_param->htemp_freq_offset);
    rwnx_get_s8_item(varbuf, len, "tssi_2g_offset", &cali_param->tssi_2g_offset);
    rwnx_get_s8_item(varbuf, len, "tssi_5g_offset_5200", &cali_param->tssi_5g_offset[0]);
    rwnx_get_s8_item(varbuf, len, "tssi_5g_offset_5400", &cali_param->tssi_5g_offset[1]);
    rwnx_get_s8_item(varbuf, len, "tssi_5g_offset_5600", &cali_param->tssi_5g_offset[2]);
    rwnx_get_s8_item(varbuf, len, "tssi_5g_offset_5800", &cali_param->tssi_5g_offset[3]);
    rwnx_get_s8_item(varbuf, len, "wf2g_spur_rmen", &cali_param->wf2g_spur_rmen);
    rwnx_get_s16_item(varbuf, len, "spur_freq", &cali_param->spur_freq);
    rwnx_get_s8_item(varbuf, len, "rf_count", &cali_param->rf_num);

    cali_param->version = version;
    cali_param->cali_config = cali_config;

    printk("======>>>>>> version = %ld\n", cali_param->version);
    printk("======>>>>>> cali_config = %d\n", cali_param->cali_config);
    printk("======>>>>>> freq_offset = %d\n", cali_param->freq_offset);
    printk("======>>>>>> htemp_freq_offset = %d\n", cali_param->htemp_freq_offset);
    printk("======>>>>>> tssi_2g_offset = 0x%x\n", cali_param->tssi_2g_offset);
    printk("======>>>>>> tssi_5g_offset_5200 = 0x%x\n", cali_param->tssi_5g_offset[0]);
    printk("======>>>>>> tssi_5g_offset_5400 = 0x%x\n", cali_param->tssi_5g_offset[1]);
    printk("======>>>>>> tssi_5g_offset_5600 = 0x%x\n", cali_param->tssi_5g_offset[2]);
    printk("======>>>>>> tssi_5g_offset_5800 = 0x%x\n", cali_param->tssi_5g_offset[3]);
    printk("======>>>>>> wf2g_spur_rmen = %d\n", cali_param->wf2g_spur_rmen);
    printk("======>>>>>> spur_freq = %d\n", cali_param->spur_freq);
    printk("======>>>>>> rf_count = %d\n", cali_param->rf_num);

    return 0;
}

static int rwnx_readFile(struct file *fp, char *buf, int len)
{
    int rlen = 0, sum = 0;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
    if (!(fp->f_mode & FMODE_CAN_READ)) {
#else
    if (!fp->f_op || !fp->f_op->read) {
#endif
        return -EPERM;
    }

    while (sum < len) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0))
        rlen = kernel_read(fp, buf + sum, len - sum, &fp->f_pos);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
        rlen = __vfs_read(fp, buf + sum, len - sum, &fp->f_pos);
#else
        rlen = fp->f_op->read(fp, buf + sum, len - sum, &fp->f_pos);
#endif
        if (rlen > 0) {
            sum += rlen;
        } else if (0 != rlen) {
            return rlen;
        } else {
            break;
        }
    }

    return sum;
}

/*
* Test if the specifi @param path is a file and readable
* If readable, @param sz is got
* @param path the path of the file to test
* @return Linux specific error code
*/
int rwnx_isFileReadable(const char *path, u32 *sz)
{
    struct file *fp;
    int ret = 0;
    mm_segment_t oldfs;
    char buf;

    fp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        ret = PTR_ERR(fp);
    } else {
        oldfs = get_fs();
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0))
        set_fs(KERNEL_DS);
#else
        set_fs(get_ds());
#endif

        if (1 != rwnx_readFile(fp, &buf, 1)) {
            ret = PTR_ERR(fp);
        }

        if (ret == 0 && sz) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0))
            *sz = i_size_read(fp->f_path.dentry->d_inode);
#else
            *sz = i_size_read(fp->f_dentry->d_inode);
#endif
        }

        set_fs(oldfs);
        filp_close(fp, NULL);
    }
    return ret;
}

unsigned char rwnx_get_cali_param(struct Cali_Param *cali_param)
{
    struct file *fp;
    struct kstat stat;
    int size, len;
    int error = 0;
    char *content =  NULL;
    mm_segment_t fs;

    unsigned int chip_id_l = 0;
    unsigned char chip_id_buf[100];

    //chip_id_l = efuse_manual_read(0xf);
    chip_id_l = chip_id_l & 0xffff;
    sprintf(chip_id_buf, "%s/aml_wifi_rf_%04x.txt", rf_conf_path, chip_id_l);
    if (rwnx_isFileReadable(chip_id_buf, NULL) != 0) {
        memset(chip_id_buf,'\0',sizeof(chip_id_buf));
        switch ((chip_id_l & 0xff00) >> 8) {
            case MODULE_ITON:
                sprintf(chip_id_buf, "%s/aml_wifi_rf_iton.txt", rf_conf_path);
                break;
            case MODULE_AMPAK:
                sprintf(chip_id_buf, "%s/aml_wifi_rf_ampak.txt", rf_conf_path);
                break;
            case MODULE_FN_LINK:
                sprintf(chip_id_buf, "%s/aml_wifi_rf_fn_link.txt", rf_conf_path);
                break;
            default:
                sprintf(chip_id_buf, "%s/aml_wifi_rf.txt", rf_conf_path);
        }
        printk("aml wifi module SN:%04x  sn txt not found, the rf config: %s\n", chip_id_l, chip_id_buf);
    } else
        printk("aml wifi module SN:%04x  the rf config: %s\n", chip_id_l, chip_id_buf);
    fs = get_fs();
    set_fs(KERNEL_DS);

    fp = filp_open(chip_id_buf, O_RDONLY, 0);

    if (IS_ERR(fp)) {
        fp = NULL;
        goto err;
    }

    error = vfs_stat(chip_id_buf, &stat);
    if (error) {
        filp_close(fp, NULL);
        goto err;
    }

    size = (int)stat.size;
    if (size <= 0) {
        filp_close(fp, NULL);
        goto err;
    }

    content = ZMALLOC(size, "wifi_cali_param", GFP_KERNEL);

    if (content == NULL) {
        filp_close(fp, NULL);
        goto err;
    }

    if (vfs_read(fp, content, size, &fp->f_pos) != size) {
        FREE(content, "wifi_cali_param");
        filp_close(fp, NULL);
        goto err;
    }

    len = rwnx_process_cali_content(content, size);
    rwnx_parse_cali_param(content, len, cali_param);

    if (chip_id_l & 0xf0) {
        if (chip_id_l & BIT(5))
            cali_param->rf_num = 2;
        else
            cali_param->rf_num = 1;
        printk("rf_cout is: %d\n", cali_param->rf_num);
    }
    FREE(content, "wifi_cali_param");
    filp_close(fp, NULL);
    set_fs(fs);

    return 0;
err:
    set_fs(fs);
    return 1;
}

void rwnx_config_cali_param(struct rwnx_hw *rwnx_hw)
{
    struct Cali_Param cali_param;
    unsigned char err = 0;

    memset((void *)&cali_param, 0, sizeof(struct Cali_Param));

    err = rwnx_get_cali_param(&cali_param);

    if (err == 0) {
        printk("%s:%d, set calibration parameter \n", __func__, __LINE__);
        rwnx_set_cali_param_req(rwnx_hw, &cali_param);
    }
    else {
        printk("%s:%d, set calibration parameter failed\n", __func__, __LINE__);
    }
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
void rwnx_cfg80211_sched_scan_results(struct wiphy *wiphy, uint64_t reqid)
{
    cfg80211_sched_scan_results(wiphy);
}
#else
void rwnx_cfg80211_sched_scan_results(struct wiphy *wiphy, uint64_t reqid)
{
    cfg80211_sched_scan_results(wiphy, reqid);
}
#endif


static int rwnx_cfg80211_sched_scan_start(struct wiphy *wiphy,
    struct net_device *dev, struct cfg80211_sched_scan_request *request)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);

    rwnx_send_sched_scan_req(rwnx_vif, request);

    return 0;
}

static int rwnx_cfg80211_sched_scan_stop(struct wiphy *wiphy, struct net_device *dev, u64 reqid)
{
    struct rwnx_vif *rwnx_vif = netdev_priv(dev);

    rwnx_send_sched_scan_stop_req(rwnx_vif, reqid);

    return 0;
}


static struct cfg80211_ops rwnx_cfg80211_ops = {
    .suspend = rwnx_cfg80211_suspend,
    .resume = rwnx_cfg80211_resume,
    .add_virtual_intf = rwnx_cfg80211_add_iface,
    .del_virtual_intf = rwnx_cfg80211_del_iface,
    .change_virtual_intf = rwnx_cfg80211_change_iface,
    .scan = rwnx_cfg80211_scan,
    .connect = rwnx_cfg80211_connect,
    .disconnect = rwnx_cfg80211_disconnect,
    .add_key = rwnx_cfg80211_add_key,
    .get_key = rwnx_cfg80211_get_key,
    .del_key = rwnx_cfg80211_del_key,
    .set_default_key = rwnx_cfg80211_set_default_key,
    .set_default_mgmt_key = rwnx_cfg80211_set_default_mgmt_key,
    .add_station = rwnx_cfg80211_add_station,
    .del_station = rwnx_cfg80211_del_station,
    .change_station = rwnx_cfg80211_change_station,
    .mgmt_tx = rwnx_cfg80211_mgmt_tx,
    .mgmt_tx_cancel_wait = rwnx_cfg80211_mgmt_tx_cancel_wait,
    .start_ap = rwnx_cfg80211_start_ap,
    .change_beacon = rwnx_cfg80211_change_beacon,
    .stop_ap = rwnx_cfg80211_stop_ap,
    .set_monitor_channel = rwnx_cfg80211_set_monitor_channel,
    .probe_client = rwnx_cfg80211_probe_client,
    .set_wiphy_params = rwnx_cfg80211_set_wiphy_params,
    .set_txq_params = rwnx_cfg80211_set_txq_params,
    .set_tx_power = rwnx_cfg80211_set_tx_power,
//    .get_tx_power = rwnx_cfg80211_get_tx_power,
    .set_power_mgmt = rwnx_cfg80211_set_power_mgmt,
    .get_station = rwnx_cfg80211_get_station,
    .dump_station = rwnx_cfg80211_dump_station,
    .remain_on_channel = rwnx_cfg80211_remain_on_channel,
    .cancel_remain_on_channel = rwnx_cfg80211_cancel_remain_on_channel,
    .dump_survey = rwnx_cfg80211_dump_survey,
    .get_channel = rwnx_cfg80211_get_channel,
    .start_radar_detection = rwnx_cfg80211_start_radar_detection,
    .update_ft_ies = rwnx_cfg80211_update_ft_ies,
    .set_cqm_rssi_config = rwnx_cfg80211_set_cqm_rssi_config,
    .channel_switch = rwnx_cfg80211_channel_switch,
    .tdls_channel_switch = rwnx_cfg80211_tdls_channel_switch,
    .tdls_cancel_channel_switch = rwnx_cfg80211_tdls_cancel_channel_switch,
    .tdls_mgmt = rwnx_cfg80211_tdls_mgmt,
    .tdls_oper = rwnx_cfg80211_tdls_oper,
    .change_bss = rwnx_cfg80211_change_bss,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
    .external_auth = rwnx_cfg80211_external_auth,
#endif
    .set_rekey_data =  rwnx_cfg80211_set_rekey_data,
    .sched_scan_start = rwnx_cfg80211_sched_scan_start,
    .sched_scan_stop = rwnx_cfg80211_sched_scan_stop,
};


/*********************************************************************
 * Init/Exit functions
 *********************************************************************/
static void rwnx_wdev_unregister(struct rwnx_hw *rwnx_hw)
{
    struct rwnx_vif *rwnx_vif, *tmp;

    rtnl_lock();
    list_for_each_entry_safe(rwnx_vif, tmp, &rwnx_hw->vifs, list) {
        rwnx_cfg80211_del_iface(rwnx_hw->wiphy, &rwnx_vif->wdev);
    }
    rtnl_unlock();
}

static void rwnx_set_vers(struct rwnx_hw *rwnx_hw)
{
    u32 vers = rwnx_hw->version_cfm.version_lmac;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    snprintf(rwnx_hw->wiphy->fw_version,
             sizeof(rwnx_hw->wiphy->fw_version), "%d.%d.%d.%d",
             (vers & (0xff << 24)) >> 24, (vers & (0xff << 16)) >> 16,
             (vers & (0xff <<  8)) >>  8, (vers & (0xff <<  0)) >>  0);

    rwnx_hw->machw_type = rwnx_machw_type(rwnx_hw->version_cfm.version_machw_2);
}

static void rwnx_reg_notifier(struct wiphy *wiphy,
                              struct regulatory_request *request)
{
    struct rwnx_hw *rwnx_hw = wiphy_priv(wiphy);

    RWNX_INFO("initiator=%d, hint_type=%d, alpha=%s, region=%d\n",
                request->initiator, request->user_reg_hint_type,
                request->alpha2, request->dfs_region);
    rwnx_apply_custom_regdom(wiphy, request->alpha2);
    // For now trust all initiator
    rwnx_radar_set_domain(&rwnx_hw->radar, request->dfs_region);
    rwnx_send_me_chan_config_req(rwnx_hw);
}

static void rwnx_enable_mesh(struct rwnx_hw *rwnx_hw)
{
    struct wiphy *wiphy = rwnx_hw->wiphy;

    if (!rwnx_mod_params.mesh)
        return;

    rwnx_cfg80211_ops.add_mpath = rwnx_cfg80211_add_mpath;
    rwnx_cfg80211_ops.del_mpath = rwnx_cfg80211_del_mpath;
    rwnx_cfg80211_ops.change_mpath = rwnx_cfg80211_change_mpath;
    rwnx_cfg80211_ops.get_mpath = rwnx_cfg80211_get_mpath;
    rwnx_cfg80211_ops.dump_mpath = rwnx_cfg80211_dump_mpath;
    rwnx_cfg80211_ops.get_mpp = rwnx_cfg80211_get_mpp;
    rwnx_cfg80211_ops.dump_mpp = rwnx_cfg80211_dump_mpp;
    rwnx_cfg80211_ops.get_mesh_config = rwnx_cfg80211_get_mesh_config;
    rwnx_cfg80211_ops.update_mesh_config = rwnx_cfg80211_update_mesh_config;
    rwnx_cfg80211_ops.join_mesh = rwnx_cfg80211_join_mesh;
    rwnx_cfg80211_ops.leave_mesh = rwnx_cfg80211_leave_mesh;

    wiphy->flags |= (WIPHY_FLAG_MESH_AUTH | WIPHY_FLAG_IBSS_RSN);
    wiphy->features |= NL80211_FEATURE_USERSPACE_MPM;
    wiphy->interface_modes |= BIT(NL80211_IFTYPE_MESH_POINT);

    rwnx_limits[0].types |= BIT(NL80211_IFTYPE_MESH_POINT);
    rwnx_limits_dfs[0].types |= BIT(NL80211_IFTYPE_MESH_POINT);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
static inline void
rwnx_wiphy_set_max_sched_scans(struct wiphy *wiphy, uint8_t max_scans)
{
    if (max_scans == 0)
        wiphy->flags &= ~WIPHY_FLAG_SUPPORTS_SCHED_SCAN;
    else
        wiphy->flags |= WIPHY_FLAG_SUPPORTS_SCHED_SCAN;
}
#else
static inline void
rwnx_wiphy_set_max_sched_scans(struct wiphy *wiphy, uint8_t max_scans)
{
    wiphy->max_sched_scan_reqs = max_scans;
}
#endif /* KERNEL_VERSION(4, 12, 0) */

/**
 * rwnx_cfg80211_add_connected_pno_support() - Set connected PNO support
 * @wiphy: Pointer to wireless phy
 *
 * This function is used to set connected PNO support to kernel
 *
 * Return: None
 */
#if defined(CFG80211_REPORT_BETTER_BSS_IN_SCHED_SCAN)
static void rwnx_cfg80211_add_connected_pno_support(struct wiphy *wiphy)
{
    wiphy_ext_feature_set(wiphy,
        NL80211_EXT_FEATURE_SCHED_SCAN_RELATIVE_RSSI);
}
#else
static void rwnx_cfg80211_add_connected_pno_support(struct wiphy *wiphy)
{
    return;
}
#endif

static int rwnx_inetaddr_event(struct notifier_block *this,unsigned long event, void *ptr) {
    struct net_device *ndev;
    struct rwnx_vif *rwnx_vif;
    struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;

    if (!ifa || !(ifa->ifa_dev->dev)) {
        return NOTIFY_DONE;
    }

    if (ifa->ifa_dev->dev->netdev_ops != &rwnx_netdev_ops) {
        return NOTIFY_DONE;
    }

    ndev = ifa->ifa_dev->dev;
    rwnx_vif = netdev_priv(ndev);

    switch (rwnx_vif->wdev.iftype) {
    case NL80211_IFTYPE_STATION:
    case NL80211_IFTYPE_P2P_CLIENT:
        if (event == NETDEV_UP) {
            int ret;
            uint8_t* ip_addr = (uint8_t*)&ifa->ifa_address;
            ret = rwnx_send_notify_ip(rwnx_vif, IPV4_VER,ip_addr);
            printk("notify ip addr,ret:%d,ip:%d.%d.%d.%d\n",ret,ip_addr[0],ip_addr[1],ip_addr[2],ip_addr[3]);
        }
        break;

    default:
        break;
    }
    return NOTIFY_DONE;
}

static int rwnx_inetaddr6_event(struct notifier_block *this,unsigned long event, void *ptr) {
    //DO STH
    return NOTIFY_DONE;
}

static struct notifier_block rwnx_ipv4_cb = {
    .notifier_call = rwnx_inetaddr_event
};

static struct notifier_block rwnx_ipv6_cb = {
    .notifier_call = rwnx_inetaddr6_event
};

/**
 *
 */
int rwnx_cfg80211_init(struct rwnx_plat *rwnx_plat, void **platform_data)
{
    struct rwnx_hw *rwnx_hw;
    struct rwnx_conf_file init_conf;
    int ret = 0;
    struct wiphy *wiphy;
    struct wireless_dev *wdev;
    char alpha2[2];
    int i;

    RWNX_DBG(RWNX_FN_ENTRY_STR);

    /* create a new wiphy for use with cfg80211 */
    wiphy = wiphy_new(&rwnx_cfg80211_ops, sizeof(struct rwnx_hw));

    if (!wiphy) {
        dev_err(rwnx_platform_get_dev(rwnx_plat), "Failed to create new wiphy\n");
        ret = -ENOMEM;
        goto err_out;
    }

    rwnx_hw = wiphy_priv(wiphy);
    rwnx_hw->wiphy = wiphy;
    rwnx_hw->plat = rwnx_plat;
    rwnx_hw->dev = rwnx_platform_get_dev(rwnx_plat);
    rwnx_hw->mod_params = &rwnx_mod_params;
    rwnx_hw->tcp_pacing_shift = 7;

    /* set device pointer for wiphy */
    set_wiphy_dev(wiphy, rwnx_hw->dev);

    /* Create cache to allocate sw_txhdr */
    rwnx_hw->sw_txhdr_cache = KMEM_CACHE(rwnx_sw_txhdr, 0);
    if (!rwnx_hw->sw_txhdr_cache) {
        wiphy_err(wiphy, "Cannot allocate cache for sw TX header\n");
        ret = -ENOMEM;
        goto err_cache;
    }

    if ((ret = rwnx_parse_configfile(rwnx_hw, RWNX_CONFIG_FW_NAME, &init_conf))) {
        wiphy_err(wiphy, "rwnx_parse_configfile failed\n");
        goto err_config;
    }

    rwnx_hw->vif_started = 0;
    rwnx_hw->monitor_vif = RWNX_INVALID_VIF;

    rwnx_hw->scan_ie.addr = NULL;

    for (i = 0; i < NX_ITF_MAX; i++)
        rwnx_hw->avail_idx_map |= BIT(i);

    printk("%s:%d\n", __func__, __LINE__);
    rwnx_hwq_init(rwnx_hw);
    rwnx_txq_prepare(rwnx_hw);

    printk("%s:%d\n", __func__, __LINE__);
    rwnx_mu_group_init(rwnx_hw);

    rwnx_hw->roc = NULL;

    memcpy(wiphy->perm_addr, init_conf.mac_addr, ETH_ALEN);
    wiphy->mgmt_stypes = rwnx_default_mgmt_stypes;

    wiphy->wowlan = &wowlan_stub;

    wiphy->bands[NL80211_BAND_2GHZ] = &rwnx_band_2GHz;
    wiphy->bands[NL80211_BAND_5GHZ] = &rwnx_band_5GHz;
    wiphy->interface_modes =
        BIT(NL80211_IFTYPE_STATION)     |
        BIT(NL80211_IFTYPE_AP)          |
        BIT(NL80211_IFTYPE_AP_VLAN)     |
        BIT(NL80211_IFTYPE_P2P_CLIENT)  |
        BIT(NL80211_IFTYPE_P2P_GO)      |
        BIT(NL80211_IFTYPE_MONITOR);
    wiphy->flags |= WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL |
        WIPHY_FLAG_HAS_CHANNEL_SWITCH |
        WIPHY_FLAG_4ADDR_STATION |
        WIPHY_FLAG_4ADDR_AP |
        WIPHY_FLAG_REPORTS_OBSS |
        WIPHY_FLAG_OFFCHAN_TX;

    /*init for pno*/
    rwnx_wiphy_set_max_sched_scans(wiphy, 1);
    wiphy->max_match_sets       = PNO_MAX_SUPP_NETWORKS;
    wiphy->max_sched_scan_ie_len = SCANU_MAX_IE_LEN;
    rwnx_cfg80211_add_connected_pno_support(wiphy);

    wiphy->max_scan_ssids = SCAN_SSID_MAX;
    wiphy->max_scan_ie_len = SCANU_MAX_IE_LEN;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
    wiphy->support_mbssid = 1;
#endif

    wiphy->max_num_csa_counters = BCN_MAX_CSA_CPT;

    wiphy->max_remain_on_channel_duration = rwnx_hw->mod_params->roc_dur_max;

    wiphy->features |= NL80211_FEATURE_NEED_OBSS_SCAN |
        NL80211_FEATURE_SK_TX_STATUS |
        NL80211_FEATURE_VIF_TXPOWER |
        NL80211_FEATURE_ACTIVE_MONITOR |
        NL80211_FEATURE_AP_MODE_CHAN_WIDTH_CHANGE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
    wiphy->features |= NL80211_FEATURE_SAE;
#endif

    wiphy->iface_combinations   = rwnx_combinations;
    /* -1 not to include combination with radar detection, will be re-added in
       rwnx_handle_dynparams if supported */
    wiphy->n_iface_combinations = ARRAY_SIZE(rwnx_combinations) - 1;
    wiphy->reg_notifier = rwnx_reg_notifier;

    alpha2[0] = '0';
    alpha2[1] = '0';
    rwnx_apply_custom_regdom(wiphy, alpha2);

    wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;

    wiphy->cipher_suites = cipher_suites;
    wiphy->n_cipher_suites = ARRAY_SIZE(cipher_suites) - NB_RESERVED_CIPHER;

    rwnx_hw->ext_capa[0] = WLAN_EXT_CAPA1_EXT_CHANNEL_SWITCHING;
    rwnx_hw->ext_capa[2] = WLAN_EXT_CAPA3_MULTI_BSSID_SUPPORT;
    rwnx_hw->ext_capa[7] = WLAN_EXT_CAPA8_OPMODE_NOTIF;

    wiphy->extended_capabilities = rwnx_hw->ext_capa;
    wiphy->extended_capabilities_mask = rwnx_hw->ext_capa;
    wiphy->extended_capabilities_len = ARRAY_SIZE(rwnx_hw->ext_capa);

#if defined(CONFIG_RWNX_PCIE_MODE)
    tasklet_init(&rwnx_hw->task, rwnx_task, (unsigned long)rwnx_hw);
#endif

    INIT_LIST_HEAD(&rwnx_hw->vifs);

    mutex_init(&rwnx_hw->dbgdump.mutex);
    spin_lock_init(&rwnx_hw->tx_lock);
    spin_lock_init(&rwnx_hw->cb_lock);

    printk("%s:%d\n", __func__, __LINE__);
    if ((ret = rwnx_platform_on(rwnx_hw, NULL)))
        goto err_platon;

    /* Reset FW */
    printk("%s:%d\n", __func__, __LINE__);
    if ((ret = rwnx_send_reset(rwnx_hw)))
        goto err_lmac_reqs;

    if ((ret = rwnx_send_version_req(rwnx_hw, &rwnx_hw->version_cfm)))
        goto err_lmac_reqs;
    rwnx_set_vers(rwnx_hw);

    if ((ret = rwnx_handle_dynparams(rwnx_hw, rwnx_hw->wiphy)))
        goto err_lmac_reqs;

    rwnx_enable_mesh(rwnx_hw);
    rwnx_radar_detection_init(&rwnx_hw->radar);

    /* Set parameters to firmware */
    rwnx_send_me_config_req(rwnx_hw);

    /* Only monitor mode supported when custom channels are enabled */
    if (rwnx_mod_params.custchan) {
        rwnx_limits[0].types = BIT(NL80211_IFTYPE_MONITOR);
        rwnx_limits_dfs[0].types = BIT(NL80211_IFTYPE_MONITOR);
    }

    if ((ret = wiphy_register(wiphy))) {
        wiphy_err(wiphy, "Could not register wiphy device\n");
        goto err_register_wiphy;
    }

    /* Work to defer processing of rx buffer */
    INIT_WORK(&rwnx_hw->defer_rx.work, rwnx_rx_deferred);
    skb_queue_head_init(&rwnx_hw->defer_rx.sk_list);

    /* Update regulatory (if needed) and set channel parameters to firmware
       (must be done after WiPHY registration) */
    printk("%s:%d\n", __func__, __LINE__);
    rwnx_custregd(rwnx_hw, wiphy);
    printk("%s:%d\n", __func__, __LINE__);
    rwnx_send_me_chan_config_req(rwnx_hw);

    *platform_data = rwnx_hw;

    if ((ret = rwnx_dbgfs_register(rwnx_hw, "rwnx"))) {
        wiphy_err(wiphy, "Failed to register debugfs entries");
        goto err_debugfs;
    }

    rtnl_lock();

    printk("%s:%d\n", __func__, __LINE__);
    /* Add an initial interface */
    wdev = rwnx_interface_add(rwnx_hw, "wlan%d", NET_NAME_UNKNOWN,
               rwnx_mod_params.custchan ? NL80211_IFTYPE_MONITOR : NL80211_IFTYPE_STATION,
               NULL);

    rtnl_unlock();

    /* register ipv4 addr notifier cb */
    ret = register_inetaddr_notifier(&rwnx_ipv4_cb);
    if (ret) {
        printk("%s failed to register ipv4 notifier(%d)!\n",__func__, ret);
    }

    /* register ipv6 addr notifier cb */
    ret = register_inet6addr_notifier(&rwnx_ipv6_cb);
    if (ret) {
        printk("%s failed to register ipv6 notifier(%d)!\n",__func__, ret);
    }

    if (!wdev) {
        wiphy_err(wiphy, "Failed to instantiate a network device\n");
        ret = -ENOMEM;
        goto err_add_interface;
    }

    wiphy_info(wiphy, "New interface create %s", wdev->netdev->name);

    rtnl_lock();

    /* Add an p2p interface */
    wdev = rwnx_interface_add(rwnx_hw, "p2p%d", NET_NAME_UNKNOWN,
               NL80211_IFTYPE_P2P_DEVICE, NULL);

    rtnl_unlock();

    if (!wdev) {
        wiphy_err(wiphy, "Failed to instantiate a p2p network device\n");
        ret = -ENOMEM;
        goto err_add_interface;
    }

    wiphy_info(wiphy, "New interface create %s", wdev->netdev->name);

    return 0;

err_add_interface:
err_debugfs:
    wiphy_unregister(rwnx_hw->wiphy);
err_register_wiphy:
err_lmac_reqs:
    rwnx_fw_trace_dump(rwnx_hw);
    rwnx_platform_off(rwnx_hw, NULL);
err_platon:
err_config:
    kmem_cache_destroy(rwnx_hw->sw_txhdr_cache);
err_cache:
    wiphy_free(wiphy);
err_out:
    return ret;
}

/**
 *
 */
void rwnx_cfg80211_deinit(struct rwnx_hw *rwnx_hw)
{
    RWNX_DBG(RWNX_FN_ENTRY_STR);

    unregister_inetaddr_notifier(&rwnx_ipv4_cb);
    unregister_inet6addr_notifier(&rwnx_ipv6_cb);

    rwnx_dbgfs_unregister(rwnx_hw);
    del_timer_sync(&rwnx_hw->txq_cleanup);
    rwnx_wdev_unregister(rwnx_hw);
    wiphy_unregister(rwnx_hw->wiphy);
    rwnx_radar_detection_deinit(&rwnx_hw->radar);
    rwnx_platform_off(rwnx_hw, NULL);
    kmem_cache_destroy(rwnx_hw->sw_txhdr_cache);
    wiphy_free(rwnx_hw->wiphy);
}

void rwnx_get_version(void)
{
    rwnx_print_version();
}

/**
 *
 */
static int __init rwnx_mod_init(void)
{
    RWNX_DBG(RWNX_FN_ENTRY_STR);
    rwnx_print_version();

    return rwnx_platform_register_drv();
}

/**
 *
 */
static void __exit rwnx_mod_exit(void)
{
    RWNX_DBG(RWNX_FN_ENTRY_STR);

    rwnx_platform_unregister_drv();
}

module_init(rwnx_mod_init);
module_exit(rwnx_mod_exit);

MODULE_FIRMWARE(RWNX_CONFIG_FW_NAME);

MODULE_DESCRIPTION(RW_DRV_DESCRIPTION);
MODULE_VERSION(RWNX_VERS_MOD);
MODULE_AUTHOR(RW_DRV_COPYRIGHT " " RW_DRV_AUTHOR);
MODULE_LICENSE("GPL");
