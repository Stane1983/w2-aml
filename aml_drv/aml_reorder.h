/**
 ****************************************************************************************
 *
 * @file aml_reorder.h
 *
 * Copyright (C) Amlogic 2012-2024
 *
 ****************************************************************************************
 */

#ifndef AML_REORDER_H_
#define AML_REORDER_H_

#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/skbuff.h>

#include <fw/dp_rx.h>

struct aml_hw;
struct aml_sta;

/* in TU (1024 microseconds) */
#define AML_REO_TIMEOUT_TU_MIN          (1)
#define AML_REO_TIMEOUT_TU_MAX          (1000)
#define AML_REO_TIMEOUT_TU_DEFAULT      { 200, 200, 200, 200, 200, 200, 200, 200, }

struct aml_reo_entry {
    unsigned long deadline;     /* in jiffies. */
    struct sk_buff *skb;        /* a mpdu (a msdu or an a-msdu) */
};

struct aml_reo_evt_record {
    s16 sn;
    u32 ts;                     /* in jiffies */
};

struct aml_reo_session {
    spinlock_t lock;

    struct aml_hw *hw;

    u8 sta_id;
    u8 tid;

    u16 buf_size;
    u16 win_size;       /* cache windows size */

    u16 timeout_tu;     /* in TU (1.024 millisecond) */
    u16 timeout_ticks;

    u16 ssn;            /* start s/n */
    u16 lsn;            /* last s/n */

    u8 suspend;         /* detect which frame is the first one after power resume */

    u8 pn_check;
    u64 pn;

    struct timer_list timer;
    unsigned long last_rx;      /* in jiffies */
    unsigned long last_aging;

    /* the last s/n and timestamp when the following event occurred */
    struct {
        struct aml_reo_evt_record bar;          /* bar or re-ADDBA */
        struct aml_reo_evt_record out_win;
        struct aml_reo_evt_record timeout;
    } last;

    struct {
        unsigned long next_dump;

        s32 in_buffer;  /* still buffered */

        u32 rx;     /* total rx packet counter */
        u32 dup;    /* duplicated MPDU counter */
        u32 miss;   /* missed MPDU counter */
        u32 stale;
        u32 out_win;
        u32 pn_err;
        u32 timeout;/* timeout times */
    } stats;

    /* the bitmap represents if the recent frame (<ssn) is delivered to system or not */
    unsigned long *delivered;

    /* NB: place holder must be the last member */
    struct aml_reo_entry buf[];
};

int aml_reo_session_create(struct aml_hw *aml_hw, u8 sta_id, u8 tid, u16 sz, u16 ssn);
int aml_reo_session_delete(struct aml_hw *aml_hw, u8 sta_id, u8 tid);

void aml_reo_sta_deinit(struct aml_hw *aml_hw, struct aml_sta *aml_sta);

struct aml_reo_session *aml_reo_session_get(struct aml_hw *aml_hw, u8 sta_id, u8 tid);
static inline void aml_reo_session_put(struct aml_reo_session *reo)
{
    spin_unlock_bh(&reo->lock);
}

int aml_reo_session_timeout_set(struct aml_reo_session *reo, u16 tu);
void aml_reo_suspend(struct aml_hw *aml_hw);
int aml_reo_bar_process(struct aml_hw *aml_hw, u8 sta_id, struct sk_buff *skb);
void aml_reo_enqueue(struct aml_reo_session *reo, struct sk_buff *skb, struct sk_buff_head *frames);

/* callback API */
void aml_reo_forward(struct aml_hw *aml_hw, struct sk_buff_head *frames);
u32 aml_rx_skb_signature(struct sk_buff *skb);

#endif /* AML_REORDER_H_ */
