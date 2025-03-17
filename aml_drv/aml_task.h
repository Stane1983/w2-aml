/**
****************************************************************************************
*
* @file aml_task.h
*
* Copyright (C) Amlogic, Inc. All rights reserved (2023).
*
* @brief Declaration of the task API mechanism.
*
****************************************************************************************
*/

#ifndef __AML_TASK_H__
#define __AML_TASK_H__

#include "aml_utils.h"
#include "aml_defs.h"

/*
 * Wi-Fi task's priority should not be higher than video decoder,
 * PS: the priority of surfaceflinger is 98 in S905L3Y (kernel 4.9).
 */
#define AML_TASK_PRI   98

#ifdef CONFIG_AML_USE_TASK

struct aml_task {
    struct task_struct  *task;
    struct semaphore    task_sem;
    struct completion   task_cmpl;
    int task_quit;
    spinlock_t lock;
};

void aml_task_init(struct aml_hw *aml_hw);
void aml_task_deinit(struct aml_hw *aml_hw);

#endif //CONFIG_AML_USE_TASK
#endif //__AML_TASK_H__
