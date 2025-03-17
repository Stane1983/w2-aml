/**
 ******************************************************************************
 *
 * @file aml_irqs.h
 *
 * Copyright (C) Amlogic 2012-2021
 *
 ******************************************************************************
 */
#ifndef _AML_IRQS_H_
#define _AML_IRQS_H_

#include <linux/interrupt.h>

/* IRQ handler to be registered by platform driver */
void aml_irq_usb_hdlr(struct urb *urb);
int aml_irq_task(void *data);

int aml_usb_irq_urb_submit(struct aml_hw *aml_hw);
void aml_usb_irq_urb_init(struct aml_hw *aml_hw, struct usb_device *udev);
void aml_usb_irq_urb_incr(struct aml_hw *aml_hw);

irqreturn_t aml_irq_sdio_hdlr(int irq, void *dev_id);
void aml_irq_sdio_hdlr_for_pt(struct sdio_func *func);
irqreturn_t aml_irq_pcie_hdlr(int irq, void *dev_id);
void aml_pcie_task(unsigned long data);

#endif /* _AML_IRQS_H_ */
