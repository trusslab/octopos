/* OctopOS mailbox hardware support layer
 * Copyright (C) 2020 Zephyr Yao <z.yao@uci.edu>
 * 
 * Based on https://lkml.org/lkml/2015/7/6/712
 */

/*
 * Copyright (c) 2015, National Instruments Corp. All rights reserved.
 *
 * Driver for the Xilinx LogiCORE mailbox IP block
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#ifdef CONFIG_ARM64

#include <linux/clk.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mailbox_controller.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/semaphore.h>
#include <linux/delay.h>
#include <linux/slab.h>
#define UNTRUSTED_DOMAIN
#define ARCH_SEC_HW
#include <octopos/mailbox.h>
#include <octopos/runtime.h>

/* register offsets */
#define MAILBOX_REG_WRDATA	0x00
#define MAILBOX_REG_RDDATA	0x08
#define MAILBOX_REG_STATUS	0x10
#define MAILBOX_REG_ERROR	0x14
#define MAILBOX_REG_SIT	0x18
#define MAILBOX_REG_RIT	0x1c
#define MAILBOX_REG_IS	0x20
#define MAILBOX_REG_IE	0x24
#define MAILBOX_REG_IP	0x28

/* octopos mailbox */
#define OWNER_MASK (u32) 0x00FFFFFF
#define QUOTA_MASK (u32) 0xFF000FFF
#define TIME_MASK  (u32) 0xFFFFF000

#define MAX_OCTOPOS_MAILBOX_QUOTE 4094
#define OCTOPOS_MAILBOX_MAX_TIME_DRIFT 10
#define OCTOPOS_MAILBOX_INTR_OFFSET 4

#define P_PREVIOUS 0xff

/* status register */
#define STS_RTA	BIT(3)
#define STS_STA	BIT(2)
#define STS_FULL	BIT(1)
#define STS_EMPTY	BIT(0)

/* error register */
#define ERR_FULL	BIT(1)
#define ERR_EMPTY	BIT(0)

/* mailbox interrupt status register */
#define INT_STATUS_ERR	BIT(2)
#define INT_STATUS_RTI	BIT(1)
#define INT_STATUS_STI	BIT(0)

/* mailbox interrupt enable register */
#define INT_ENABLE_ERR	BIT(2)
#define INT_ENABLE_RTI	BIT(1)
#define INT_ENABLE_STI	BIT(0)

#define MBOX_POLLING_MS		5	/* polling interval 5ms */

#define MAILBOX_DEFAULT_RX_THRESHOLD		MAILBOX_QUEUE_MSG_SIZE/4 - 1
#define MAILBOX_DEFAULT_RX_THRESHOLD_LARGE		MAILBOX_QUEUE_MSG_SIZE_LARGE/4 - 1

/* compatible data */
enum octopos_mailbox_version {
	SIMPLE_MAILBOX_V2_1,
	OCTOPOS_MAILBOX_V1_0,
};

int write_syscall_response(uint8_t *buf);
extern struct semaphore interrupts[NUM_QUEUES + 1];
extern uint8_t cmd_buf[MAILBOX_QUEUE_MSG_SIZE - 1];
extern struct semaphore cmd_sem;

struct xilinx_mbox {
	int irq;
	int id;
	uint8_t qid;
	void __iomem *mbox_base;
	struct clk *clk;
	struct device *dev;
};

struct octopos_mbox_ctrl {
	int irq;
	int id;
	uint8_t qid;
	void __iomem *ctrl_base;
	struct clk *clk;
	struct device *dev;
	struct xilinx_mbox *ref_mbox;
};

void* mbox_map[NUM_QUEUES + 1] = {0};
EXPORT_SYMBOL(mbox_map);

void* mbox_ctrl_map[NUM_QUEUES + 1] = {0};
EXPORT_SYMBOL(mbox_ctrl_map);

static const struct of_device_id xilinx_mbox_match[] = {
	{ .compatible = "xlnx,Octopos_mailbox",
		.data = (void *)OCTOPOS_MAILBOX_V1_0 },
	{ .compatible = "xlnx,mailbox-2.1", 
		.data = (void *)SIMPLE_MAILBOX_V2_1 },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, xilinx_mbox_match);

static inline bool xilinx_mbox_full(struct xilinx_mbox *mbox)
{
	u32 status;

	status = readl_relaxed(mbox->mbox_base + MAILBOX_REG_STATUS);

	return status & STS_FULL;
}

static inline bool xilinx_mbox_pending(struct xilinx_mbox *mbox)
{
	u32 status;

	status = readl_relaxed(mbox->mbox_base + MAILBOX_REG_STATUS);

	return !(status & STS_EMPTY);
}

static inline bool xilinx_mbox_empty(struct xilinx_mbox *mbox)
{
	u32 status;

	status = readl_relaxed(mbox->mbox_base + MAILBOX_REG_STATUS);

	return status & STS_EMPTY;
}

static void xilinx_mbox_intmask(struct xilinx_mbox *mbox, u32 mask, bool enable)
{
	u32 mask_reg;

	mask_reg = readl_relaxed(mbox->mbox_base + MAILBOX_REG_IE);
	if (enable)
		mask_reg |= mask;
	else
		mask_reg &= ~mask;

	writel_relaxed(mask_reg, mbox->mbox_base + MAILBOX_REG_IE);
}

static inline void xilinx_mbox_rx_intmask(struct xilinx_mbox *mbox, bool enable)
{
	xilinx_mbox_intmask(mbox, INT_ENABLE_RTI, enable);
}

static inline void xilinx_mbox_tx_intmask(struct xilinx_mbox *mbox, bool enable)
{
	xilinx_mbox_intmask(mbox, INT_ENABLE_STI, enable);
}

static inline void xilinx_mbox_irq_send_data_hw(struct xilinx_mbox *mbox, u32 data)
{
	writel_relaxed(data, mbox->mbox_base + MAILBOX_REG_WRDATA);
}

static inline u32 xilinx_mbox_irq_receive_data_hw(struct xilinx_mbox *mbox)
{
	return readl_relaxed(mbox->mbox_base + MAILBOX_REG_RDDATA);
}

static inline void octopos_mbox_clear_interrupt(struct octopos_mbox_ctrl *mbox_ctrl)
{
	writel_relaxed(1, mbox_ctrl->ctrl_base + OCTOPOS_MAILBOX_INTR_OFFSET);
}

static void xilinx_mbox_receiver_and_clear_data(struct xilinx_mbox *mbox)
{
	if (xilinx_mbox_pending(mbox))
		xilinx_mbox_irq_receive_data_hw(mbox);
}

static void xilinx_mbox_tx_set_threshold(struct xilinx_mbox *mbox, u32 value)
{
	writel_relaxed(value, mbox->mbox_base + MAILBOX_REG_SIT);
}

static void xilinx_mbox_rx_set_threshold(struct xilinx_mbox *mbox, u32 value)
{
	writel_relaxed(value, mbox->mbox_base + MAILBOX_REG_RIT);
}

u32 octopos_mailbox_get_status_reg(
	struct octopos_mbox_ctrl *mbox_ctrl)
{
	return readl_relaxed(mbox_ctrl->ctrl_base);
}
EXPORT_SYMBOL(octopos_mailbox_get_status_reg);

void octopos_mailbox_set_status_reg(
	struct octopos_mbox_ctrl *mbox_ctrl, 
	u32 value)
{
	writel_relaxed(value, mbox_ctrl->ctrl_base);
}
EXPORT_SYMBOL(octopos_mailbox_set_status_reg);

int xilinx_mbox_receive_data_blocking(struct xilinx_mbox *mbox, 
									u32 *buffer, 
									u32 buffer_size)
{
	u32 bytes_read;

	if (!mbox) {
		dev_err(mbox->dev, "no mbox instance.\n");
		return -ENXIO;
	}

	if (!buffer) {
		dev_err(mbox->dev, "no buffer.\n");
		return -EFAULT;
	}

	if (buffer_size == 0) {
		dev_err(mbox->dev, "size cannot be zero.\n");
		return -EFAULT;
	}

	if ((buffer_size % 4) != 0) {
		dev_err(mbox->dev, "size must be in multiples of 4.\n");
		return -EFAULT;
	}

	if ((u32) buffer & 0x3) {
		dev_err(mbox->dev, "buffer not aligned.\n");
		return -EFAULT;
	}

	bytes_read = 0;

	// if (mbox->qid != Q_OSU && mbox->qid != Q_UNTRUSTED)
	// 	printk("%08x", octopos_mailbox_get_status_reg(mbox_ctrl_map[mbox->qid]));

	do {
		while(xilinx_mbox_empty(mbox));

		*buffer++ =
			xilinx_mbox_irq_receive_data_hw(mbox);
		bytes_read += 4;
	} while (bytes_read != buffer_size);

	return 0;
}
EXPORT_SYMBOL(xilinx_mbox_receive_data_blocking);

int xilinx_mbox_send_data_blocking(struct xilinx_mbox *mbox, 
								u32 *buffer, 
								u32 buffer_size)
{
	u32 bytes_written;

	if (!mbox) {
		dev_err(mbox->dev, "no mbox instance.\n");
		return -ENXIO;
	}

	if (!buffer) {
		dev_err(mbox->dev, "no buffer.\n");
		return -EFAULT;
	}

	if (buffer_size == 0) {
		dev_err(mbox->dev, "size cannot be zero.\n");
		return -EFAULT;
	}

	if ((buffer_size % 4) != 0) {
		dev_err(mbox->dev, "size must be in multiples of 4.\n");
		return -EFAULT;
	}

	if ((u32) buffer & 0x3) {
		dev_err(mbox->dev, "buffer not aligned.\n");
		return -EFAULT;
	}

	bytes_written = 0;

	do {
		while (xilinx_mbox_full(mbox));

		xilinx_mbox_irq_send_data_hw(mbox,
			*buffer++);
		bytes_written += 4;
	} while (bytes_written != buffer_size);

	return 0;
}
EXPORT_SYMBOL(xilinx_mbox_send_data_blocking);

/* Temporary owner of the mailbox cannot delegate full quota to another
 * owner (or switch back to the OS). So we must take one off from the
 * read limit and time limit quotas.
 */
static void octopos_mailbox_deduct_and_set_owner(
	struct octopos_mbox_ctrl *mbox_ctrl, 
	u8 owner)
{
	//u32 reg = octopos_mailbox_get_status_reg(mbox_ctrl) - 0x1001;
	//reg = (OWNER_MASK & reg) | owner << 24;

	//octopos_mailbox_set_status_reg(mbox_ctrl, reg);
	octopos_mailbox_set_status_reg(mbox_ctrl, 0xFF000000);
}

int octopos_mailbox_attest_owner_fast_hw(struct octopos_mbox_ctrl *mbox_ctrl)
{
	return 0xDEAFBEEF != octopos_mailbox_get_status_reg(mbox_ctrl);
}
EXPORT_SYMBOL(octopos_mailbox_attest_owner_fast_hw);

int octopos_mailbox_attest_quota_limit_hw(
	struct octopos_mbox_ctrl *mbox_ctrl, 
	u16 limit)
{
	return limit == (u16) (octopos_mailbox_get_status_reg(mbox_ctrl) >> 12 & 0xfff);
}
EXPORT_SYMBOL(octopos_mailbox_attest_quota_limit_hw);

int octopos_mailbox_attest_time_limit_lower_bound_hw(
	struct octopos_mbox_ctrl *mbox_ctrl, 
	u16 limit)
{
	return limit <= (u16) (octopos_mailbox_get_status_reg(mbox_ctrl) & 0xfff);
}
EXPORT_SYMBOL(octopos_mailbox_attest_time_limit_lower_bound_hw);

int octopos_mailbox_attest_time_limit_hw(
	struct octopos_mbox_ctrl *mbox_ctrl, 
	u16 limit)
{
	return limit == (u16) (octopos_mailbox_get_status_reg(mbox_ctrl) & 0xfff);
}
EXPORT_SYMBOL(octopos_mailbox_attest_time_limit_hw);

void mailbox_yield_to_previous_owner_hw(struct octopos_mbox_ctrl *mbox_ctrl)
{
	uint8_t queue_id = mbox_ctrl->qid;

	if (queue_id > NUM_QUEUES)
		BUG();

	/* This delay waits for the receiver to finish reading */
	/* FIXME: replace with a reliable waiting mechanism */
	udelay(100);
	octopos_mailbox_deduct_and_set_owner(mbox_ctrl, P_PREVIOUS);
}
EXPORT_SYMBOL(mailbox_yield_to_previous_owner_hw);

static irqreturn_t xilinx_mbox_interrupt(int irq, void *p)
{
	u32 mask;
	struct xilinx_mbox *mbox = (struct xilinx_mbox *)p;
	uint8_t *buf;

	mask = readl_relaxed(mbox->mbox_base + MAILBOX_REG_IS);
	// dev_err(mbox->dev, "irq %d mask = %d\n", irq, mask);

	if (mask & INT_STATUS_RTI) {
		switch(mbox->qid) {
		case Q_UNTRUSTED:
			buf = (uint8_t*) kcalloc(MAILBOX_QUEUE_MSG_SIZE, 
				sizeof(uint8_t), 
				GFP_KERNEL);
			xilinx_mbox_receive_data_blocking(mbox, 
				(u32*) buf, 
				MAILBOX_QUEUE_MSG_SIZE);
			if (buf[0] == RUNTIME_QUEUE_SYSCALL_RESPONSE_TAG) {
				write_syscall_response(buf);
				up(&interrupts[Q_UNTRUSTED]);
			} else if (buf[0] == RUNTIME_QUEUE_EXEC_APP_TAG) {
				memcpy(cmd_buf, &buf[1], MAILBOX_QUEUE_MSG_SIZE - 1);
				up(&cmd_sem);
			} else {
				dev_err(mbox->dev, "invalid message (%d).\n", buf[0]);
				BUG();
			}
			break;
		case Q_STORAGE_CMD_OUT:
		case Q_STORAGE_DATA_OUT:
		case Q_NETWORK_DATA_OUT:
			// if (interrupt == Q_NETWORK_DATA_OUT)
			// 	schedule_work(&net_wq);
			up(&interrupts[mbox->qid]);
			break;
		default :
			dev_err(mbox->dev, "invalid mbox (%d).\n", mbox->qid);
			BUG();
			break;
		}
	} else if (mask & INT_STATUS_STI) {
		switch(mbox->qid) {
		case Q_OSU:
		case Q_STORAGE_CMD_IN:
		case Q_STORAGE_DATA_IN:
		case Q_NETWORK_DATA_IN:
			up(&interrupts[mbox->qid]);
			break;
		default :
			dev_err(mbox->dev, "invalid mbox (%d).\n", mbox->qid);
			BUG();
			break;
		}
	}

	writel_relaxed(mask, mbox->mbox_base + MAILBOX_REG_IS);

	return IRQ_HANDLED;
}

static irqreturn_t octopos_mbox_ctrl_interrupt(int irq, void *p)
{
	struct octopos_mbox_ctrl *mbox_ctrl = (struct octopos_mbox_ctrl *)p;
	struct xilinx_mbox *mbox = mbox_ctrl->ref_mbox;

	if(unlikely(!mbox)) {
		dev_err(mbox->dev, "missing reference mbox.\n");
		BUG();
	}

	uint8_t queue_id = mbox_ctrl->qid;
	// dev_err(mbox->dev, "irq %d queue id = %d\n", irq, queue_id);

	octopos_mbox_clear_interrupt(mbox_ctrl);

	switch (queue_id) {
		case Q_STORAGE_CMD_OUT:
			xilinx_mbox_rx_intmask(mbox, true);
			xilinx_mbox_rx_set_threshold(mbox, MAILBOX_DEFAULT_RX_THRESHOLD);
			break;
		case Q_STORAGE_DATA_OUT:
			xilinx_mbox_rx_intmask(mbox, true);
			xilinx_mbox_rx_set_threshold(mbox, MAILBOX_DEFAULT_RX_THRESHOLD_LARGE);
			break;
		case Q_STORAGE_CMD_IN:
		case Q_STORAGE_DATA_IN:
			xilinx_mbox_tx_intmask(mbox, true);
			xilinx_mbox_tx_set_threshold(mbox, 0);
			break;
		case Q_NETWORK_DATA_IN:
		case Q_NETWORK_DATA_OUT:
		default:
			dev_err(mbox->dev, "invalid mbox (%d).\n", mbox->qid);
			BUG();
			break;
	}

	return IRQ_HANDLED;
}

static uint8_t find_mbox_by_name(const char* dev_name)
{
	uint8_t queue_id;

	if (strcmp(dev_name, "a0000000.mailbox") == 0)
		queue_id = Q_OSU;
	else if (strcmp(dev_name, "a0001000.mailbox") == 0)
		queue_id = Q_UNTRUSTED;
	else
		return 0;

	return queue_id;
}

static uint8_t find_mbox_ctrl_by_name(const char* dev_name)
{
	uint8_t queue_id;

	if (strcmp(dev_name, "a0070000.Octopos_mailbox") == 0)
		queue_id = Q_STORAGE_DATA_IN;
	else if (strcmp(dev_name, "a0080000.Octopos_mailbox") == 0)
		queue_id = Q_STORAGE_DATA_OUT;
	else if (strcmp(dev_name, "a0004000.Octopos_mailbox") == 0)
		queue_id = Q_STORAGE_CMD_IN;
	else if (strcmp(dev_name, "a0008000.Octopos_mailbox") == 0)
		queue_id = Q_STORAGE_CMD_OUT;
	else if (strcmp(dev_name, "a0010000.Octopos_mailbox") == 0)
		queue_id = Q_NETWORK_DATA_IN;
	else if (strcmp(dev_name, "a0020000.Octopos_mailbox") == 0)
		queue_id = Q_NETWORK_DATA_OUT;
	else if (strcmp(dev_name, "a0030000.Octopos_mailbox") == 0)
		queue_id = Q_NETWORK_CMD_IN;
	else if (strcmp(dev_name, "a0040000.Octopos_mailbox") == 0)
		queue_id = Q_NETWORK_CMD_OUT;
	else
		return 0;

	return queue_id;
}

static void init_mbox_thresholds(struct xilinx_mbox *mbox, 
								uint8_t queue_id)
{
	switch(queue_id) {
	case Q_OSU:
		xilinx_mbox_tx_intmask(mbox, true);
		xilinx_mbox_tx_set_threshold(mbox, 0);
		break;
	case Q_UNTRUSTED:
		xilinx_mbox_rx_intmask(mbox, true);
		xilinx_mbox_rx_set_threshold(mbox, MAILBOX_DEFAULT_RX_THRESHOLD);
		break;
	default :
		/* other queues must be set when the OctopOS
		 * mailbox ownership change.
		 */
		break;
   }
}

static int xilinx_mbox_probe(struct platform_device *pdev)
{
	const struct of_device_id *of_id;
	struct xilinx_mbox *mbox;
	struct octopos_mbox_ctrl *mbox_ctrl;
	struct resource	*regs_ctrl;
	struct resource	*regs_data;
	int ret;
	uint8_t queue_id;
	enum octopos_mailbox_version version;

	/* recognize the type of mbox */
	of_id = of_match_node(xilinx_mbox_match, (&pdev->dev)->of_node);
    version = (enum octopos_mailbox_version)of_id->data;

    switch(version) {
	case SIMPLE_MAILBOX_V2_1:
		mbox = devm_kzalloc(&pdev->dev, sizeof(*mbox), GFP_KERNEL);
		if (!mbox)
			return -ENOMEM;

		/* get clk and enable */
		mbox->clk = devm_clk_get(&pdev->dev, "S1_AXI_ACLK");
		if (IS_ERR(mbox->clk)) {
			dev_err(&pdev->dev, "Couldn't get clk.\n");
			return PTR_ERR(mbox->clk);
		}

		/* get and map mbox data register */
		regs_data = platform_get_resource(pdev, IORESOURCE_MEM, 0);

		mbox->mbox_base = devm_ioremap_resource(&pdev->dev, regs_data);
		if (IS_ERR(mbox->mbox_base))
			return PTR_ERR(mbox->mbox_base);

		/* get and config mbox data irq */
		mbox->id = &pdev->id;
		mbox->irq = platform_get_irq(pdev, 0);
		dev_info(&pdev->dev, "xmbox: IRQ = %d\n", mbox->irq);

		if (mbox->irq <= 0) {
			dev_err(&pdev->dev, "IRQ not found.\n");
			return -EINTR;
		}

		mbox->dev = &pdev->dev;

		ret = devm_request_irq(&pdev->dev, mbox->irq, xilinx_mbox_interrupt, IRQF_SHARED,
				  dev_name(mbox->dev), mbox);
//		dev_info(&pdev->dev, "[1] %d\n", ret);

		if (unlikely(ret)) {
			dev_err(mbox->dev, 
				"failed to register mailbox interrupt:%d\n",
				ret);
			return ret;
		}

		/* prep and enable the clock */
		clk_prepare_enable(mbox->clk);
//		dev_info(&pdev->dev, "[2]\n");

		/* if fifo was full already, we won't get an interrupt */
		if (unlikely(xilinx_mbox_pending(mbox))) {
			dev_err(mbox->dev, "mbox is full at init time.\n");
			while (xilinx_mbox_pending(mbox))
				xilinx_mbox_receiver_and_clear_data(mbox);
		}
//		dev_info(&pdev->dev, "[3]\n");

		/* read queue type and id based on dev name */
		queue_id = find_mbox_by_name(dev_name(mbox->dev));
//		dev_info(&pdev->dev, "[4] %d\n", queue_id);
		if (unlikely(queue_id == 0)) {
			dev_err(mbox->dev, "Invalid device name.\n");
			return -ENXIO;
		}
		mbox->qid = queue_id;

		init_mbox_thresholds(mbox, queue_id);
//		dev_info(&pdev->dev, "[5]\n");
		
		/* save device info */
		mbox_map[queue_id] = mbox;
		platform_set_drvdata(pdev, mbox);
//		dev_info(&pdev->dev, "[6]\n");
		break;
	case OCTOPOS_MAILBOX_V1_0:
		mbox_ctrl = devm_kzalloc(&pdev->dev, sizeof(*mbox_ctrl), GFP_KERNEL);
		if (!mbox_ctrl)
			return -ENOMEM;

		mbox = devm_kzalloc(&pdev->dev, sizeof(*mbox), GFP_KERNEL);
		if (!mbox)
			return -ENOMEM;
//		dev_info(&pdev->dev, "[1]\n");

		/* get clk and enable */
		mbox_ctrl->clk = devm_clk_get(&pdev->dev, "s_ctrl3_axi_aclk");
		if (IS_ERR(mbox_ctrl->clk)) {
			dev_err(&pdev->dev, "Couldn't get clk.\n");
			return PTR_ERR(mbox_ctrl->clk);
		}

		mbox->clk = devm_clk_get(&pdev->dev, "S0_data3_AXI_ACLK");
		if (IS_ERR(mbox->clk)) {
			dev_err(&pdev->dev, "Couldn't get clk.\n");
			return PTR_ERR(mbox->clk);
		}
//		dev_info(&pdev->dev, "[2]\n");

		/* get and map mbox ctrl register */
		regs_ctrl = platform_get_resource(pdev, IORESOURCE_MEM, 0);

		mbox_ctrl->ctrl_base = devm_ioremap_resource(&pdev->dev, regs_ctrl);
		if (IS_ERR(mbox_ctrl->ctrl_base))
			return PTR_ERR(mbox_ctrl->ctrl_base);
//		dev_info(&pdev->dev, "[3] %08x\n", regs_ctrl->start);
//		dev_info(&pdev->dev, "-> %08x\n", mbox_ctrl->ctrl_base);

		/* get and map mbox data register */
		regs_data = platform_get_resource(pdev, IORESOURCE_MEM, 1);

		mbox->mbox_base = devm_ioremap_resource(&pdev->dev, regs_data);
		if (IS_ERR(mbox->mbox_base))
			return PTR_ERR(mbox->mbox_base);
//		dev_info(&pdev->dev, "[4] %08x\n", regs_data->start);
//		dev_info(&pdev->dev, "-> %08x\n", mbox->mbox_base);

		/* get and config mbox ctrl irq */
		mbox_ctrl->id = &pdev->id;
		mbox_ctrl->irq = platform_get_irq(pdev, 0);
//		dev_info(&pdev->dev, "ctrl IRQ = %d\n", mbox_ctrl->irq);

		if (mbox_ctrl->irq <= 0) {
			dev_err(&pdev->dev, "IRQ not found.\n");
			return -EINTR;
		}

		/* get and config mbox data irq */
		mbox->id = &pdev->id; 
		mbox->irq = platform_get_irq(pdev, 1);
//		dev_info(&pdev->dev, "data IRQ = %d\n", mbox->irq);

		if (mbox->irq <= 0) {
			dev_err(&pdev->dev, "IRQ not found.\n");
			return -EINTR;
		}

		mbox_ctrl->dev = &pdev->dev;
		mbox->dev = &pdev->dev;

		ret = devm_request_irq(&pdev->dev, mbox_ctrl->irq, octopos_mbox_ctrl_interrupt, IRQF_SHARED,
				  dev_name(mbox_ctrl->dev), mbox_ctrl);

		if (unlikely(ret)) {
			dev_err(mbox_ctrl->dev, 
				"failed to register mailbox ctrl interrupt:%d\n",
				ret);
			return ret;
		}
//		dev_info(&pdev->dev, "[5]\n");

		ret = devm_request_irq(&pdev->dev, mbox->irq, xilinx_mbox_interrupt, IRQF_SHARED,
				  dev_name(mbox->dev), mbox);

		if (unlikely(ret)) {
			dev_err(mbox->dev, 
				"failed to register mailbox data interrupt:%d\n",
				ret);
			return ret;
		}
//		dev_info(&pdev->dev, "[6]\n");

		/* prep and enable the clock */
		clk_prepare_enable(mbox_ctrl->clk);
		clk_prepare_enable(mbox->clk);

		/* read queue type and id based on dev name */
		queue_id = find_mbox_ctrl_by_name(dev_name(mbox_ctrl->dev));
		if (unlikely(queue_id == 0)) {
			dev_err(mbox_ctrl->dev, "Invalid device name.\n");
			BUG();
		}
		mbox_ctrl->qid = queue_id;
		mbox->qid = queue_id;

//		dev_info(&pdev->dev, "[7] %d\n", queue_id);

//		dev_info(&pdev->dev, "%08x", 
//			octopos_mailbox_get_status_reg(mbox_ctrl));

		init_mbox_thresholds(mbox, queue_id);
//		dev_info(&pdev->dev, "[9]\n");

		/* save device info */
		mbox_ctrl_map[queue_id] = mbox_ctrl;
		mbox_map[queue_id] = mbox;
		mbox_ctrl->ref_mbox = mbox;

		platform_set_drvdata(pdev, mbox_ctrl);
		break;
	default:
		BUG();
		break;
    }

	return 0;
}

static int xilinx_mbox_remove(struct platform_device *pdev)
{
	/* Currently nothing to clean up */
	return 0;
}

static struct platform_driver xilinx_mbox_driver = {
	.probe	= xilinx_mbox_probe,
	.remove	= xilinx_mbox_remove,
	.driver	= {
		.name	= KBUILD_MODNAME,
		.of_match_table	= of_match_ptr(xilinx_mbox_match),
	},
};

module_platform_driver(xilinx_mbox_driver);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Support Xilinx hardware mailbox");
MODULE_AUTHOR("Zephyr Yao <z.yao@uci.edu>");

#endif
