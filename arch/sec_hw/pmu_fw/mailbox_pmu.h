#ifdef ARCH_SEC_HW_PMU

#ifndef _MAILBOX_PMU_H_
#define _MAILBOX_PMU_H_

/* queue IDs */
#define	Q_OS1			1
#define	Q_OS2			2
#define	Q_KEYBOARD		3
#define	Q_SERIAL_OUT		4
#define	Q_STORAGE_DATA_IN	5
#define	Q_STORAGE_DATA_OUT	6
#define	Q_STORAGE_CMD_IN	7
#define	Q_STORAGE_CMD_OUT	8
#define	Q_STORAGE_IN_2		9
#define	Q_STORAGE_OUT_2		10
#define	Q_NETWORK_DATA_IN	11
#define	Q_NETWORK_DATA_OUT	12
#define	Q_NETWORK_CMD_IN	13
#define	Q_NETWORK_CMD_OUT	14
#define Q_SENSOR		15
#define	Q_RUNTIME1		16
#define	Q_RUNTIME2		17
#define NUM_QUEUES		17

u32 octopos_mailbox_get_status_reg(UINTPTR base);

void mailbox_print_queue_status(uint8_t queue_id);

void pmu_initialize_octopos_mbox();


#endif /* _MAILBOX_PMU_H_ */

#endif /* ARCH_SEC_HW_PMU */
