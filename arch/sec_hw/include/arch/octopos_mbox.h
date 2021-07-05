#ifndef __ARCH_OCTOPOS_MBOX_H_
#define __ARCH_OCTOPOS_MBOX_H_

#if defined(PROJ_CPP)
#define _Bool bool
#endif

#define OWNER_MASK (u32) 0x00FFFFFF
#define QUOTA_MASK (u32) 0xFF000FFF
#define TIME_MASK  (u32) 0xFFFFF000

#define MAX_OCTOPOS_MAILBOX_QUOTE 4094
#define OCTOPOS_MAILBOX_MAX_TIME_DRIFT 10

/***************************************************************/
/* Mailbox ctrl access parameters                              */
/***************************************************************/
/* mailbox ctrl register addresses mapped to OS */
#define OCTOPOS_OS_Q_KEYBOARD_BASEADDR 0x43605000
#define OCTOPOS_OS_Q_SERIAL_OUT_BASEADDR 0x43603000
#define OCTOPOS_OS_Q_RUNTIME1_BASEADDR 0x43607000
#define OCTOPOS_OS_Q_RUNTIME2_BASEADDR 0x43609000
#define OCTOPOS_OS_Q_STORAGE_DATA_IN_BASEADDR 0x43610000
#define OCTOPOS_OS_Q_STORAGE_DATA_OUT_BASEADDR 0x4360B000
#define OCTOPOS_OS_Q_STORAGE_IN_2_BASEADDR 0x43612000
#define OCTOPOS_OS_Q_STORAGE_OUT_2_BASEADDR 0x4360D000

/* mailbox ctrl register addresses mapped to Microblaze 0 and 1 */
#define OCTOPOS_SERIAL_MAILBOX_1WRI_0_BASEADDR 0x44A00000
#define OCTOPOS_SERIAL_MAILBOX_STORAGE_DATA_OUT_BASEADDR 0x44A10000

/* mailbox ctrl register addresses mapped to Microblaze 2 and 3 */
#define OCTOPOS_ENCLAVE_MAILBOX_1WRI_0_BASEADDR 0x44A00000
#define OCTOPOS_ENCLAVE_MAILBOX_3WRI_0_BASEADDR 0x44A10000
#define OCTOPOS_ENCLAVE_MAILBOX_3WRI_1_BASEADDR 0x44A20000
#define OCTOPOS_ENCLAVE_MAILBOX_3WRI_2_BASEADDR 0x44A30000
#define OCTOPOS_ENCLAVE_Q_STORAGE_DATA_IN_BASEADDR 0x44A34000
#define OCTOPOS_ENCLAVE_Q_STORAGE_DATA_OUT_BASEADDR 0x44A32000
#define OCTOPOS_ENCLAVE_Q_STORAGE_IN_2_BASEADDR 0x44A38000
#define OCTOPOS_ENCLAVE_Q_STORAGE_OUT_2_BASEADDR 0x44A36000

/* mailbox ctrl register addresses mapped to Microblaze 4 */
#define OCTOPOS_STORAGE_Q_STORAGE_DATA_IN_BASEADDR 0x43605000
#define OCTOPOS_STORAGE_Q_STORAGE_DATA_OUT_BASEADDR 0x43603000
#define OCTOPOS_STORAGE_Q_STORAGE_IN_2_BASEADDR 0x43609000
#define OCTOPOS_STORAGE_Q_STORAGE_OUT_2_BASEADDR 0x43607000

/***************************************************************/
/* Mailbox data access parameters                              */
/***************************************************************/
#if defined ARCH_SEC_HW_OS
#define XPAR_MBOX_NUM_INSTANCES 12U
#elif defined ARCH_SEC_HW_STORAGE
#define XPAR_MBOX_NUM_INSTANCES 4U
#elif defined ARCH_SEC_HW_RUNTIME
#define XPAR_MBOX_NUM_INSTANCES 9U
#elif defined ARCH_SEC_HW_KEYBOARD
#define XPAR_MBOX_NUM_INSTANCES 2U
#elif defined ARCH_SEC_HW_SERIAL_OUT
#define XPAR_MBOX_NUM_INSTANCES 2U
#endif

/* mailboxs connected to Serial out (Microblaze 0) */
#define XPAR_SERIAL_OUT_SERIAL_OUT_DEVICE_ID 0U
#define XPAR_SERIAL_OUT_SERIAL_OUT_BASEADDR 0x41210000U
#define XPAR_SERIAL_OUT_SERIAL_OUT_USE_FSL 0U
#define XPAR_SERIAL_OUT_SERIAL_OUT_SEND_FSL 0U
#define XPAR_SERIAL_OUT_SERIAL_OUT_RECV_FSL 0U

#define XPAR_SERIAL_OUT_STORAGE_DATA_OUT_DEVICE_ID 1U
#define XPAR_SERIAL_OUT_STORAGE_DATA_OUT_BASEADDR 0x41220000U
#define XPAR_SERIAL_OUT_STORAGE_DATA_OUT_USE_FSL 0U
#define XPAR_SERIAL_OUT_STORAGE_DATA_OUT_SEND_FSL 0U
#define XPAR_SERIAL_OUT_STORAGE_DATA_OUT_RECV_FSL 0U

/* mailboxs connected to Keyboard (Microblaze 1) */
#define XPAR_KEYBOARD_KEYBOARD_DEVICE_ID 0U
#define XPAR_KEYBOARD_KEYBOARD_BASEADDR 0x41210000U
#define XPAR_KEYBOARD_KEYBOARD_USE_FSL 0U
#define XPAR_KEYBOARD_KEYBOARD_SEND_FSL 0U
#define XPAR_KEYBOARD_KEYBOARD_RECV_FSL 0U

#define XPAR_KEYBOARD_STORAGE_DATA_OUT_DEVICE_ID 1U
#define XPAR_KEYBOARD_STORAGE_DATA_OUT_BASEADDR 0x41220000U
#define XPAR_KEYBOARD_STORAGE_DATA_OUT_USE_FSL 0U
#define XPAR_KEYBOARD_STORAGE_DATA_OUT_SEND_FSL 0U
#define XPAR_KEYBOARD_STORAGE_DATA_OUT_RECV_FSL 0U

/* mailboxs connected to Runtime (Microblaze 2,3) */
// FIXME: set the same addresses for MB 2 and 3
#if RUNTIME_ID == 1
#define XPAR_RUNTIME_KEYBOARD_DEVICE_ID 0U
#define XPAR_RUNTIME_KEYBOARD_BASEADDR 0x41221000U
#define XPAR_RUNTIME_KEYBOARD_USE_FSL 0U
#define XPAR_RUNTIME_KEYBOARD_SEND_FSL 0U
#define XPAR_RUNTIME_KEYBOARD_RECV_FSL 0U

#define XPAR_RUNTIME_SERIAL_OUT_DEVICE_ID 1U
#define XPAR_RUNTIME_SERIAL_OUT_BASEADDR 0x41220000U
#define XPAR_RUNTIME_SERIAL_OUT_USE_FSL 0U
#define XPAR_RUNTIME_SERIAL_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_SERIAL_OUT_RECV_FSL 0U

#define XPAR_RUNTIME_RUNTIME1_DEVICE_ID 2U
#define XPAR_RUNTIME_RUNTIME1_BASEADDR 0x41250000U
#define XPAR_RUNTIME_RUNTIME1_USE_FSL 0U
#define XPAR_RUNTIME_RUNTIME1_SEND_FSL 0U
#define XPAR_RUNTIME_RUNTIME1_RECV_FSL 0U

#define XPAR_RUNTIME_RUNTIME2_DEVICE_ID 3U
#define XPAR_RUNTIME_RUNTIME2_BASEADDR 0x41240000U
#define XPAR_RUNTIME_RUNTIME2_USE_FSL 0U
#define XPAR_RUNTIME_RUNTIME2_SEND_FSL 0U
#define XPAR_RUNTIME_RUNTIME2_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_DATA_IN_DEVICE_ID 4U
#define XPAR_RUNTIME_STORAGE_DATA_IN_BASEADDR 0x44A33000U
#define XPAR_RUNTIME_STORAGE_DATA_IN_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_IN_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_IN_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_DATA_OUT_DEVICE_ID 5U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_BASEADDR 0x44A31000U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_CMD_IN_DEVICE_ID 6U
#define XPAR_RUNTIME_STORAGE_CMD_IN_BASEADDR 0x44A40000U
#define XPAR_RUNTIME_STORAGE_CMD_IN_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_IN_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_IN_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_CMD_OUT_DEVICE_ID 7U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_BASEADDR 0x44A35000U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_RECV_FSL 0U

#define XPAR_RUNTIME_OS_DEVICE_ID 8U
#define XPAR_RUNTIME_OS_BASEADDR 0x41230000U
#define XPAR_RUNTIME_OS_USE_FSL 0U
#define XPAR_RUNTIME_OS_SEND_FSL 0U
#define XPAR_RUNTIME_OS_RECV_FSL 0U
#elif RUNTIME_ID == 2
#define XPAR_RUNTIME_KEYBOARD_DEVICE_ID 0U
#define XPAR_RUNTIME_KEYBOARD_BASEADDR 0x41210000U
#define XPAR_RUNTIME_KEYBOARD_USE_FSL 0U
#define XPAR_RUNTIME_KEYBOARD_SEND_FSL 0U
#define XPAR_RUNTIME_KEYBOARD_RECV_FSL 0U

#define XPAR_RUNTIME_SERIAL_OUT_DEVICE_ID 1U
#define XPAR_RUNTIME_SERIAL_OUT_BASEADDR 0x41220000U
#define XPAR_RUNTIME_SERIAL_OUT_USE_FSL 0U
#define XPAR_RUNTIME_SERIAL_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_SERIAL_OUT_RECV_FSL 0U

#define XPAR_RUNTIME_RUNTIME1_DEVICE_ID 2U
#define XPAR_RUNTIME_RUNTIME1_BASEADDR 0x41250000U
#define XPAR_RUNTIME_RUNTIME1_USE_FSL 0U
#define XPAR_RUNTIME_RUNTIME1_SEND_FSL 0U
#define XPAR_RUNTIME_RUNTIME1_RECV_FSL 0U

#define XPAR_RUNTIME_RUNTIME2_DEVICE_ID 3U
#define XPAR_RUNTIME_RUNTIME2_BASEADDR 0x41240000U
#define XPAR_RUNTIME_RUNTIME2_USE_FSL 0U
#define XPAR_RUNTIME_RUNTIME2_SEND_FSL 0U
#define XPAR_RUNTIME_RUNTIME2_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_DATA_IN_DEVICE_ID 4U
#define XPAR_RUNTIME_STORAGE_DATA_IN_BASEADDR 0x44A33000U
#define XPAR_RUNTIME_STORAGE_DATA_IN_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_IN_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_IN_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_DATA_OUT_DEVICE_ID 5U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_BASEADDR 0x44A31000U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_CMD_IN_DEVICE_ID 6U
#define XPAR_RUNTIME_STORAGE_CMD_IN_BASEADDR 0x44A40000U
#define XPAR_RUNTIME_STORAGE_CMD_IN_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_IN_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_IN_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_CMD_OUT_DEVICE_ID 7U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_BASEADDR 0x44A35000U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_RECV_FSL 0U

#define XPAR_RUNTIME_OS_DEVICE_ID 8U
#define XPAR_RUNTIME_OS_BASEADDR 0x41230000U
#define XPAR_RUNTIME_OS_USE_FSL 0U
#define XPAR_RUNTIME_OS_SEND_FSL 0U
#define XPAR_RUNTIME_OS_RECV_FSL 0U
#endif

/* mailboxs connected to Storage (Microblaze 4) */
#define XPAR_STORAGE_MBOX_DATA_IN_DEVICE_ID 0U
#define XPAR_STORAGE_MBOX_DATA_IN_BASEADDR 0x43604000U
#define XPAR_STORAGE_MBOX_DATA_IN_USE_FSL 0U
#define XPAR_STORAGE_MBOX_DATA_IN_SEND_FSL 0U
#define XPAR_STORAGE_MBOX_DATA_IN_RECV_FSL 0U

#define XPAR_STORAGE_MBOX_DATA_OUT_DEVICE_ID 1U
#define XPAR_STORAGE_MBOX_DATA_OUT_BASEADDR 0x43602000U
#define XPAR_STORAGE_MBOX_DATA_OUT_USE_FSL 0U
#define XPAR_STORAGE_MBOX_DATA_OUT_SEND_FSL 0U
#define XPAR_STORAGE_MBOX_DATA_OUT_RECV_FSL 0U

#define XPAR_STORAGE_MBOX_CMD_IN_DEVICE_ID 2U
#define XPAR_STORAGE_MBOX_CMD_IN_BASEADDR 0x43610000U
#define XPAR_STORAGE_MBOX_CMD_IN_USE_FSL 0U
#define XPAR_STORAGE_MBOX_CMD_IN_SEND_FSL 0U
#define XPAR_STORAGE_MBOX_CMD_IN_RECV_FSL 0U

#define XPAR_STORAGE_MBOX_CMD_OUT_DEVICE_ID 3U
#define XPAR_STORAGE_MBOX_CMD_OUT_BASEADDR 0x43606000U
#define XPAR_STORAGE_MBOX_CMD_OUT_USE_FSL 0U
#define XPAR_STORAGE_MBOX_CMD_OUT_SEND_FSL 0U
#define XPAR_STORAGE_MBOX_CMD_OUT_RECV_FSL 0U

/* mailboxs connected to OS (Microblaze 6) */
#define XPAR_OS_MBOX_Q_KEYBOARD_DEVICE_ID 0U
#define XPAR_OS_MBOX_Q_KEYBOARD_BASEADDR 0x43604000U
#define XPAR_OS_MBOX_Q_KEYBOARD_USE_FSL 0U
#define XPAR_OS_MBOX_Q_KEYBOARD_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_KEYBOARD_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_SERIAL_OUT_DEVICE_ID 1U
#define XPAR_OS_MBOX_Q_SERIAL_OUT_BASEADDR 0x43602000U
#define XPAR_OS_MBOX_Q_SERIAL_OUT_USE_FSL 0U
#define XPAR_OS_MBOX_Q_SERIAL_OUT_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_SERIAL_OUT_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_RUNTIME1_DEVICE_ID 2U
#define XPAR_OS_MBOX_Q_RUNTIME1_BASEADDR 0x43606000U
#define XPAR_OS_MBOX_Q_RUNTIME1_USE_FSL 0U
#define XPAR_OS_MBOX_Q_RUNTIME1_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_RUNTIME1_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_RUNTIME2_DEVICE_ID 3U
#define XPAR_OS_MBOX_Q_RUNTIME2_BASEADDR 0x43608000U
#define XPAR_OS_MBOX_Q_RUNTIME2_USE_FSL 0U
#define XPAR_OS_MBOX_Q_RUNTIME2_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_RUNTIME2_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_STORAGE_DATA_IN_DEVICE_ID 4U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_IN_BASEADDR 0x4360E000U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_IN_USE_FSL 0U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_IN_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_IN_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_DEVICE_ID 5U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_BASEADDR 0x4360A000U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_USE_FSL 0U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_CMD_IN_DEVICE_ID 6U
#define XPAR_OS_MBOX_Q_CMD_IN_BASEADDR 0x43611000U
#define XPAR_OS_MBOX_Q_CMD_IN_USE_FSL 0U
#define XPAR_OS_MBOX_Q_CMD_IN_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_CMD_IN_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_CMD_OUT_DEVICE_ID 7U
#define XPAR_OS_MBOX_Q_CMD_OUT_BASEADDR 0x4360C000U
#define XPAR_OS_MBOX_Q_CMD_OUT_USE_FSL 0U
#define XPAR_OS_MBOX_Q_CMD_OUT_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_CMD_OUT_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_ENCLAVE0_DEVICE_ID 8U
#define XPAR_OS_MBOX_Q_ENCLAVE0_BASEADDR 0x43600000U
#define XPAR_OS_MBOX_Q_ENCLAVE0_USE_FSL 0U
#define XPAR_OS_MBOX_Q_ENCLAVE0_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_ENCLAVE0_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_ENCLAVE1_DEVICE_ID 9U
#define XPAR_OS_MBOX_Q_ENCLAVE1_BASEADDR 0x43601000U
#define XPAR_OS_MBOX_Q_ENCLAVE1_USE_FSL 0U
#define XPAR_OS_MBOX_Q_ENCLAVE1_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_ENCLAVE1_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_UNTRUSTED_DEVICE_ID 10
#define XPAR_OS_MBOX_Q_UNTRUSTED_BASEADDR 0x43621000U
#define XPAR_OS_MBOX_Q_UNTRUSTED_USE_FSL 0U
#define XPAR_OS_MBOX_Q_UNTRUSTED_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_UNTRUSTED_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_OSU_DEVICE_ID 11
#define XPAR_OS_MBOX_Q_OSU_BASEADDR 0x43620000U
#define XPAR_OS_MBOX_Q_OSU_USE_FSL 0U
#define XPAR_OS_MBOX_Q_OSU_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_OSU_RECV_FSL 0U

u32 octopos_mailbox_get_status_reg(UINTPTR base);
void octopos_mailbox_set_status_reg(UINTPTR base, u32 value);
u8 octopos_mailbox_get_owner(UINTPTR base);
void octopos_mailbox_set_owner(UINTPTR base, u8 owner);
u16 octopos_mailbox_get_quota_limit(UINTPTR base);
void octopos_mailbox_set_quota_limit(UINTPTR base, u16 limit);
u16 octopos_mailbox_get_time_limit(UINTPTR base);
void octopos_mailbox_set_time_limit(UINTPTR base, u16 limit);
u32 octopos_mailbox_calc_owner(u32 reg, u8 owner);
u32 octopos_mailbox_calc_quota_limit(u32 reg, u16 limit);
u32 octopos_mailbox_calc_time_limit(u32 reg, u16 limit);
_Bool octopos_mailbox_attest_owner(UINTPTR base, u8 owner);
_Bool octopos_mailbox_attest_owner_fast(UINTPTR base);
_Bool octopos_mailbox_attest_quota_limit(UINTPTR base, u16 limit);
_Bool octopos_mailbox_attest_time_limit(UINTPTR base, u16 limit);
_Bool octopos_mailbox_attest_time_limit_lower_bound(UINTPTR base, u16 limit);
void octopos_mailbox_clear_interrupt(UINTPTR base);
void octopos_mailbox_deduct_and_set_owner(UINTPTR base, u8 owner);

#endif /* __ARCH_OCTOPOS_MBOX_H_ */
