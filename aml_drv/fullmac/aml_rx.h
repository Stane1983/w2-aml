/**
 ******************************************************************************
 *
 * @file aml_rx.h
 *
 * Copyright (C) Amlogic 2012-2021
 *
 ******************************************************************************
 */
#ifndef _AML_RX_H_
#define _AML_RX_H_

#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include "hal_desc.h"
#include "ipc_shared.h"
#include "aml_log.h"
#include "wifi_w2_shared_mem_cfg.h"
#include "aml_static_buf.h"
#include "aml_reorder.h"

#define BUFFER_STATUS           (BIT(0) | BIT(1))
#define BUFFER_NARROW           BIT(0)
#define BUFFER_EXPAND           BIT(1)
#define BUFFER_UPDATE_FLAG      BIT(2)
#define BUFFER_REDUCE_FINISH     BIT(3)
#define BUFFER_WRAP             BIT(4)
#define BUFFER_EXPEND_FINISH     BIT(5)
#define BUFFER_TX_USED_FLAG     BIT(6)

#define RXDESC_CNT_READ_ONCE 32

#define AML_FW_PATCHED  /* highlight the fields that firmware changed(patched) its usage */

typedef u32 addr32_t;

#ifdef CONFIG_AML_W2L_RX_MINISIZE           /* W2L compressed RX descriptor */

struct rx_hd   /* = f/w: struct rxdesc_new */
{
    uint16_t frmlen;
    uint16_t ampdu_stat_info;
#ifdef AML_FW_PATCHED
    u8 payl_offset;
    u8 status;
    u16 hostid;             /* for SDIO/USB: = SN + 1 */
    struct {
        uint16_t hostid;
        u8 len;
        u8 tid:3;
        u8 pad:4;
        u8 valid:1;         /* SDIO_RX_REORDER_FlG */
    } reorder;
#else
    uint32_t tsflo;
    uint32_t tsfhi;
#endif

    struct rx_vector_1 rx_vec_1;
#ifdef AML_FW_PATCHED
    /* struct rx_info { */
        uint32_t new_read;
        /// Id of the buffer (0 or 1)
        uint8_t buf_id;
        uint8_t patched: 1; /* RXMINISIZE_FLAGS_TSFLO_IS_RX_STATUS */
        uint8_t reserve: 7;
        /// Total length of the received buffer include padding for 4-byte alignment
        uint16_t frmlen_padded;
    /* }; */
#else
    struct rx_vector_2 rx_vec_2;
#endif

    uint32_t statinfo;
    struct phy_channel_info phy_info;
    uint32_t flag;
};

struct rxdesc {
    struct {
        struct rx_hd hd;
    } dma_hdrdesc;
};

#elif defined(CONFIG_AML_W2_RX_MINISIZE)    /* W2 compressed RX descriptor */

#error "FIXME: remove CONFIG_AML_W2_RX_MINISIZE, actually it doesn't work due to hardware issues"

#else                                       /* W2 non-compressed RX descriptor */

struct rx_upload_cntrl_tag {
    u32 fw_internal_use[5];
};

/// Element in the pool of RX header descriptor.
struct rx_hd
{
    /// Unique pattern for receive DMA.
    uint32_t            upatternrx;
    /// Pointer to the location of the next Header Descriptor
    uint32_t            next;
    /// Pointer to the first payload buffer descriptor
    uint32_t            first_pbd_ptr;
    /// Pointer to the SW descriptor associated with this HW descriptor
    addr32_t            rxdesc;
#ifdef AML_FW_PATCHED
    struct {
        u16 hostid;
        u16 pad;

        u8 len;
        u8 tid;
        u16 reserved;
    } reorder;
    u8 payl_offset;
    u8 status;
    u16 hostid;
#else
    /// Pointer to the address in buffer where the hardware should start writing the data
    uint32_t            datastartptr;
    /// Pointer to the address in buffer where the hardware should stop writing data
    uint32_t            dataendptr;
    /// Header control information. Except for a single bit which is used for enabling the
    /// Interrupt for receive DMA rest of the fields are reserved
    uint32_t            headerctrlinfo;
#endif

    /// Total length of the received MPDU
    uint16_t            frmlen;
    /// AMPDU status information
    uint16_t            ampdu_stat_info;
    /// TSF Low
    uint32_t            tsflo;
    /// TSF High
    uint32_t            tsfhi;
    /// Rx Vector 1
    struct rx_vector_1  rx_vec_1;
    /// Rx Vector 2
    struct rx_vector_2  rx_vec_2;
    /// MPDU status information
    uint32_t            statinfo;
};

struct rx_dmadesc
{
    /// Rx header descriptor (this element MUST be the first of the structure)
    struct rx_hd hd;
    /// Structure containing the information about the PHY channel that was used for this RX
    struct phy_channel_info phy_info;

    /// Word containing some SW flags about the RX packet
    uint32_t flags;
    /// Spare room for LMAC FW to write a pattern when last DMA is sent
    uint32_t pattern;
    /// IPC DMA control structure for MAC Header transfer
    struct dma_desc dma_desc;
};

struct rxdesc
{
    /// Upload control element. Shall be the first element of the RX descriptor structure
    struct rx_upload_cntrl_tag upload_cntrl;
    /// HW descriptors
    struct rx_dmadesc dma_hdrdesc;
    /// Address of the expected HW descriptor following the present in the RX buffer one,
    /// and that should be used to set to the read pointer to free the buffer
    uint32_t new_read;
    /// Id of the buffer (0 or 1)
    uint8_t buf_id;
};

/// Element in the pool of rx payload buffer descriptors.
struct rx_pbd
{
    /// Unique pattern
    uint32_t            upattern;
    /// Points to the next payload buffer descriptor of the MPDU when the MPDU is split
    /// over several buffers
    uint32_t            next;
    /// Points to the address in the buffer where the data starts
    uint32_t            datastartptr;
    /// Points to the address in the buffer where the data ends
    uint32_t            dataendptr;
    /// buffer status info for receive DMA.
    uint16_t            bufstatinfo;
    /// complete length of the buffer in memory
    uint16_t            reserved;
};

struct rx_payloaddesc
{
    /// Mac header buffer (this element MUST be the first of the structure)
    struct rx_pbd pbd;
    /// IPC DMA control structures
#define NX_DMADESC_PER_RX_PDB_CNT   1
    struct dma_desc dma_desc[NX_DMADESC_PER_RX_PDB_CNT];
};
#endif

#ifdef CONFIG_AML_W2L_RX_MINISIZE

#define RX_DESC_SIZE                   ((u32)sizeof(struct rxdesc))
#define RX_HEADER_OFFSET               ((u32)offsetof(struct rxdesc, dma_hdrdesc.hd.frmlen))
#define RX_PD_LEN                      (0)

#elif defined(CONFIG_AML_W2_RX_MINISIZE)    /* FIXME: remove this section, it doesn't work */

#define RX_DESC_SIZE                   (80)
#define RX_HEADER_OFFSET               (28)
#define RX_PD_LEN                      (20)
#define RX_PAYLOAD_OFFSET              (RX_DESC_SIZE + RX_PD_LEN)

#define RX_HOSTID_OFFSET               (36)
#define RX_REORDER_LEN_OFFSET          (38)
#define RX_STATUS_OFFSET               (32)
#define RX_FRMLEN_OFFSET               (28)
#define NEXT_PKT_OFFSET                (56)

#else /* W2 layout */

#define RX_DESC_SIZE                   ((u32)sizeof(struct rxdesc))
#define RX_HEADER_OFFSET               ((u32)offsetof(struct rxdesc, dma_hdrdesc.hd.frmlen))
#define RX_PD_LEN                      ((u32)sizeof(struct rx_payloaddesc))

#endif

enum rx_status_bits
{
    /// The buffer can be forwarded to the networking stack
    RX_STAT_FORWARD = 1 << 0,
    /// A new buffer has to be allocated
    RX_STAT_ALLOC = 1 << 1,
    /// The buffer has to be deleted
    RX_STAT_DELETE = 1 << 2,
    /// The length of the buffer has to be updated
    RX_STAT_LEN_UPDATE = 1 << 3,
    /// The length in the Ethernet header has to be updated
    RX_STAT_ETH_LEN_UPDATE = 1 << 4,
    /// Simple copy
    RX_STAT_COPY = 1 << 5,
    /// Spurious frame (inform upper layer and discard)
    RX_STAT_SPURIOUS = 1 << 6,
    /// packet for monitor interface
    RX_STAT_MONITOR = 1 << 7,

    /// Host reorder (combine two counter flags)
    RX_STAT_HOST_REO = (RX_STAT_ALLOC | RX_STAT_DELETE),
};

/* Maximum number of rx buffer the fw may use at the same time
   (must be at least IPC_RXBUF_CNT) */
#define AML_RXBUFF_MAX ((64 * NX_MAX_MSDU_PER_RX_AMSDU * NX_REMOTE_STA_MAX) < IPC_RXBUF_CNT ?     \
                         IPC_RXBUF_CNT : (64 * NX_MAX_MSDU_PER_RX_AMSDU * NX_REMOTE_STA_MAX))

/**
 * struct aml_skb_cb - Control Buffer structure for RX buffer
 *
 * @hostid: Buffer identifier. Written back by fw in RX descriptor to identify
 * the associated rx buffer
 */
struct aml_skb_cb {
    uint32_t hostid;
};

#define AML_RXBUFF_HOSTID_SET(buf, val)                                \
    ((struct aml_skb_cb *)((struct sk_buff *)buf->addr)->cb)->hostid = val

#define AML_RXBUFF_HOSTID_GET(buf)                                        \
    ((struct aml_skb_cb *)((struct sk_buff *)buf->addr)->cb)->hostid

#define AML_RXBUFF_VALID_IDX(idx) ((idx) < AML_RXBUFF_MAX)

/* Used to ensure that hostid set to fw is never 0 */
#define AML_RXBUFF_IDX_TO_HOSTID(idx) ((idx) + 1)
#define AML_RXBUFF_HOSTID_TO_IDX(hostid) ((hostid) - 1)

#define RX_MACHDR_BACKUP_LEN    64

/// MAC header backup descriptor
struct mon_machdrdesc
{
    /// Length of the buffer
    u32 buf_len;
    /// Buffer containing mac header, LLC and SNAP
    u8 buffer[RX_MACHDR_BACKUP_LEN];
};

struct hw_rxhdr {
    /** RX vector */
    struct hw_vect hwvect;

    /** PHY channel information */
    struct phy_channel_info_desc phy_info;

    /** RX flags */
    u32 flags_is_amsdu     : 1;
    u32 flags_is_80211_mpdu: 1;
    u32 flags_is_4addr     : 1;
    u32 flags_new_peer     : 1;
    u32 flags_user_prio    : 3;
    u32 flags_rsvd0        : 1;
    u32 flags_vif_idx      : 8;    // 0xFF if invalid VIF index
    u32 flags_sta_idx      : 8;    // 0xFF if invalid STA index
    u32 flags_dst_idx      : 8;    // 0xFF if unknown destination STA
#ifdef CONFIG_AML_MON_DATA
    /// MAC header backup descriptor (used only for MSDU when there is a monitor and a data interface)
    struct mon_machdrdesc mac_hdr_backup;
#endif
    /** Pattern indicating if the buffer is available for the driver */
    u32 pattern;
    u32 reserved[6];
    u32 amsdu_hostids[NX_MAX_MSDU_PER_RX_AMSDU - 1];
    u16 amsdu_len[NX_MAX_MSDU_PER_RX_AMSDU];
};

/* SDIO/USB only */
#define AML_RHD_EXT(rhd)   (struct aml_rhd_ext *)(&((struct hw_rxhdr *)(rhd))->pattern)

/**
 * struct aml_defer_rx - Defer rx buffer processing
 *
 * @skb: List of deferred buffers
 * @work: work to defer processing of this buffer
 */
struct aml_defer_rx {
    struct sk_buff_head sk_list;
    struct work_struct work;
};

/**
 * struct aml_defer_rx_cb - Control buffer for deferred buffers
 *
 * @vif: VIF that received the buffer
 */
struct aml_defer_rx_cb {
    struct aml_vif *vif;
};

#ifdef CONFIG_AML_SDIO_USB_FW_REORDER
struct rxdata {
    struct list_head list;
    struct sk_buff *skb;
    u16 hostid;
    u8 tid;
};

struct fw_reo_info {
    u16 hostid;
    u16 pad;
    u8 reorder_len;
    u8 tid;
    u16 flag;
};
#endif

struct debug_proc_rxbuff_info {
    u32 time;
    u32 addr;
    u32 hostid;
    u16 status;
    u16 buff_idx;
    u16 idx;
};

struct debug_push_rxdesc_info {
    u32 time;
    u32 addr;
    u16 idx;
};

struct debug_push_rxbuff_info {
    u32 time;
    u32 addr;
    u32 hostid;
    u16 idx;
};

struct rxbuf_list{
    struct list_head list;

    u8 *rxbuf;                  /* host memory used to store the copy of rx buf in firmware */

    /*
     * host memory segment 1: from rxbuf to gap;
     * host memory segment 2: from gap to end
     * NB: segment 2 only exists if rxbuf_data_start > rxbuf_data_end (wrapped)
     */
    u8 *gap;
    u8 *end;

    u8 *pos;                    /* current rx desc position in host memory */
    u32 fw_pos;                 /* current rx desc position in firmware memory */

    u32 rx_buf_end;             /* rx buf's end address in firmware (it's scalable) */
    u32 rxbuf_data_start;       /* first frame's start address in firmware */
    u32 rxbuf_data_end;         /* last frame's end address in firmware */
};

struct aml_dyn_snr_cfg {
    bool need_trial;
    unsigned int best_snr_cfg;
    unsigned int enable;
    unsigned int snr_mcs_ration;
    u64 rx_byte_1; //trial 1
    u64 rx_byte_2; //trial 2
    u64 rx_byte;   //all rx bytes
    //struct aml_rx_rate_stats rx_rate;
    unsigned long last_time;
};

#define DEBUG_RX_BUF_CNT       300

#define AML_WRAP CO_BIT(31)
#define RX_DATA_MAX_CNT (512 + 128)

#define RXBUF_SIZE (324 * 1024)
#define RXBUF_NUM (WLAN_AML_HW_RX_SIZE / RXBUF_SIZE)

u8 aml_unsup_rx_vec_ind(void *pthis, void *hostid);
u8 aml_rxdataind(void *pthis, void *hostid);
void aml_rx_deferred(struct work_struct *ws);
void aml_rx_defer_skb(struct aml_hw *aml_hw, struct aml_vif *aml_vif,
                       struct sk_buff *skb);

void aml_scan_clear_scan_res(struct aml_hw *aml_hw);
void aml_scan_rx(struct aml_hw *aml_hw, struct hw_rxhdr *hw_rxhdr, struct sk_buff *skb);
void aml_rxbuf_list_init(struct aml_hw *aml_hw);

#ifdef CONFIG_AML_SDIO_USB_FW_REORDER
void aml_rxdata_init(void);
void aml_rxdata_deinit(void);
void aml_clear_reorder_list();
#endif

#ifndef CONFIG_AML_DEBUGFS
void aml_dealloc_global_rx_rate(struct aml_hw *aml_hw, struct aml_sta *sta);
#endif
#endif /* _AML_RX_H_ */
