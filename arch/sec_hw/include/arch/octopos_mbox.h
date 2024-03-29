/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
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
#define OCTOPOS_OS_Q_KEYBOARD_BASEADDR 0xF1840000
#define OCTOPOS_OS_Q_SERIAL_OUT_BASEADDR 0xF1870000
#define OCTOPOS_OS_Q_RUNTIME1_BASEADDR 0xF0820000
#define OCTOPOS_OS_Q_RUNTIME2_BASEADDR 0xF0840000
#define OCTOPOS_OS_Q_STORAGE_DATA_IN_BASEADDR 0xF1890000
#define OCTOPOS_OS_Q_STORAGE_DATA_OUT_BASEADDR 0xF18A0000
#define OCTOPOS_OS_Q_STORAGE_IN_2_BASEADDR 0xF18D0000
#define OCTOPOS_OS_Q_STORAGE_OUT_2_BASEADDR 0xF18F0000
#define OCTOPOS_OS_Q_NETWORK_DATA_IN_BASEADDR 0xF0870000
#define OCTOPOS_OS_Q_NETWORK_DATA_OUT_BASEADDR 0xF0890000
#define OCTOPOS_OS_Q_NETWORK_IN_2_BASEADDR 0xF08A0000
#define OCTOPOS_OS_Q_NETWORK_OUT_2_BASEADDR 0xF08C0000

/* mailbox ctrl register addresses mapped to Microblaze 0 (serial out) */
#define OCTOPOS_SERIAL_OUT_MAILBOX_1WRI_0_BASEADDR 0xF0830000U
#define OCTOPOS_SERIAL_OUT_MAILBOX_STORAGE_DATA_OUT_BASEADDR 0xF0850000U

/* mailbox ctrl register addresses mapped to Microblaze 1 (Keyboard) */
#define OCTOPOS_KEYBOARD_MAILBOX_1WRI_0_BASEADDR 0xF0830000U
#define OCTOPOS_KEYBOARD_SERIAL_MAILBOX_STORAGE_DATA_OUT_BASEADDR 0xF0840000U

/* mailbox ctrl register addresses mapped to Microblaze 2 (enclave 1) */
#define OCTOPOS_ENCLAVE_1_MAILBOX_KEYBOARD_BASEADDR 0xF1800000
#define OCTOPOS_ENCLAVE_1_MAILBOX_SERIAL_OUT_BASEADDR 0xF1820000
#define OCTOPOS_ENCLAVE_1_MAILBOX_RUNTIME2_BASEADDR 0xF0860000
#define OCTOPOS_ENCLAVE_1_MAILBOX_RUNTIME1_BASEADDR 0xF0840000
#define OCTOPOS_ENCLAVE_1_Q_STORAGE_DATA_IN_BASEADDR 0xF1840000
#define OCTOPOS_ENCLAVE_1_Q_STORAGE_DATA_OUT_BASEADDR 0xF1860000
#define OCTOPOS_ENCLAVE_1_Q_STORAGE_IN_2_BASEADDR 0xF1880000
#define OCTOPOS_ENCLAVE_1_Q_STORAGE_OUT_2_BASEADDR 0xF1890000
#define OCTOPOS_ENCLAVE_1_Q_NETWORK_DATA_IN_BASEADDR 0xF0880000
#define OCTOPOS_ENCLAVE_1_Q_NETWORK_DATA_OUT_BASEADDR 0xF08A0000
#define OCTOPOS_ENCLAVE_1_Q_NETWORK_IN_2_BASEADDR 0xF08B0000
#define OCTOPOS_ENCLAVE_1_Q_NETWORK_OUT_2_BASEADDR 0xF08D0000

/* mailbox ctrl register addresses mapped to Microblaze 3 (enclave 2) */
#define OCTOPOS_ENCLAVE_2_MAILBOX_KEYBOARD_BASEADDR 0xF08F0000
#define OCTOPOS_ENCLAVE_2_MAILBOX_SERIAL_OUT_BASEADDR 0xF1810000
#define OCTOPOS_ENCLAVE_2_MAILBOX_RUNTIME2_BASEADDR 0xF0840000
#define OCTOPOS_ENCLAVE_2_MAILBOX_RUNTIME1_BASEADDR 0xF0810000
#define OCTOPOS_ENCLAVE_2_Q_STORAGE_DATA_IN_BASEADDR 0xF1830000
#define OCTOPOS_ENCLAVE_2_Q_STORAGE_DATA_OUT_BASEADDR 0xF1850000
#define OCTOPOS_ENCLAVE_2_Q_STORAGE_IN_2_BASEADDR 0xF1870000
#define OCTOPOS_ENCLAVE_2_Q_STORAGE_OUT_2_BASEADDR 0xF1890000
#define OCTOPOS_ENCLAVE_2_Q_NETWORK_DATA_IN_BASEADDR 0xF0860000
#define OCTOPOS_ENCLAVE_2_Q_NETWORK_DATA_OUT_BASEADDR 0xF0890000
#define OCTOPOS_ENCLAVE_2_Q_NETWORK_IN_2_BASEADDR 0xF08A0000
#define OCTOPOS_ENCLAVE_2_Q_NETWORK_OUT_2_BASEADDR 0xF08C0000

/* mailbox ctrl register addresses mapped to storage domain */
#define OCTOPOS_STORAGE_Q_STORAGE_DATA_IN_BASEADDR 0xF0860000
#define OCTOPOS_STORAGE_Q_STORAGE_DATA_OUT_BASEADDR 0xF0890000
#define OCTOPOS_STORAGE_Q_STORAGE_IN_2_BASEADDR 0xF08B0000
#define OCTOPOS_STORAGE_Q_STORAGE_OUT_2_BASEADDR 0xF08C0000

/* mailbox ctrl register addresses mapped to Microblaze 5 (network domain) */
#define OCTOPOS_NETWORK_Q_NETWORK_DATA_IN_BASEADDR 0xF08A0000
#define OCTOPOS_NETWORK_Q_NETWORK_DATA_OUT_BASEADDR 0xF08B0000
#define OCTOPOS_NETWORK_Q_NETWORK_IN_2_BASEADDR 0xF08E0000
#define OCTOPOS_NETWORK_Q_NETWORK_OUT_2_BASEADDR 0xF1800000
#define OCTOPOS_NETWORK_Q_NETWORK_ARBITTER_BASEADDR 0xF0880000
#define OCTOPOS_NETWORK_Q_STORAGE_DATA_OUT_BASEADDR 0xF1820000U

/***************************************************************/
/* Mailbox data access parameters                              */
/***************************************************************/
#if defined ARCH_SEC_HW_OS
#define XPAR_MBOX_NUM_INSTANCES 17U
#elif defined ARCH_SEC_HW_STORAGE
#define XPAR_MBOX_NUM_INSTANCES 5U
#elif defined ARCH_SEC_HW_RUNTIME
#define XPAR_MBOX_NUM_INSTANCES 14U
#elif defined ARCH_SEC_HW_KEYBOARD
#define XPAR_MBOX_NUM_INSTANCES 3U
#elif defined ARCH_SEC_HW_SERIAL_OUT
#define XPAR_MBOX_NUM_INSTANCES 3U
#elif defined ARCH_SEC_HW_NETWORK
#define XPAR_MBOX_NUM_INSTANCES 6U
#endif

/* TPM mailbox connected to each domain, which share the same address */
#define XPAR_TPM_DEVICE_ID 99U
#define XPAR_TPM_DEVICE_BASEADDRESS 0xF1990000U
#define XPAR_TPM_DEVICE_USE_FSL 0U
#define XPAR_TPM_DEVICE_SEND_FSL 0U
#define XPAR_TPM_DEVICE_RECV_FSL 0U

/* mailboxs connected to Serial out (Microblaze 0) */
#define XPAR_SERIAL_OUT_SERIAL_OUT_DEVICE_ID 0U
#define XPAR_SERIAL_OUT_SERIAL_OUT_BASEADDR 0xF0820000U
#define XPAR_SERIAL_OUT_SERIAL_OUT_USE_FSL 0U
#define XPAR_SERIAL_OUT_SERIAL_OUT_SEND_FSL 0U
#define XPAR_SERIAL_OUT_SERIAL_OUT_RECV_FSL 0U

#define XPAR_SERIAL_OUT_STORAGE_DATA_OUT_DEVICE_ID 1U
#define XPAR_SERIAL_OUT_STORAGE_DATA_OUT_BASEADDR 0xF0840000U
#define XPAR_SERIAL_OUT_STORAGE_DATA_OUT_USE_FSL 0U
#define XPAR_SERIAL_OUT_STORAGE_DATA_OUT_SEND_FSL 0U
#define XPAR_SERIAL_OUT_STORAGE_DATA_OUT_RECV_FSL 0U

/* mailboxs connected to Keyboard (Microblaze 1) */
#define XPAR_KEYBOARD_KEYBOARD_DEVICE_ID 0U
#define XPAR_KEYBOARD_KEYBOARD_BASEADDR 0xF0820000U
#define XPAR_KEYBOARD_KEYBOARD_USE_FSL 0U
#define XPAR_KEYBOARD_KEYBOARD_SEND_FSL 0U
#define XPAR_KEYBOARD_KEYBOARD_RECV_FSL 0U

#define XPAR_KEYBOARD_STORAGE_DATA_OUT_DEVICE_ID 1U
#define XPAR_KEYBOARD_STORAGE_DATA_OUT_BASEADDR 0xF0850000U
#define XPAR_KEYBOARD_STORAGE_DATA_OUT_USE_FSL 0U
#define XPAR_KEYBOARD_STORAGE_DATA_OUT_SEND_FSL 0U
#define XPAR_KEYBOARD_STORAGE_DATA_OUT_RECV_FSL 0U

/* mailboxs connected to Runtime (Microblaze 2,3) */
#if RUNTIME_ID == 1
#define XPAR_RUNTIME_KEYBOARD_DEVICE_ID 0U
#define XPAR_RUNTIME_KEYBOARD_BASEADDR 0xF08F0000U
#define XPAR_RUNTIME_KEYBOARD_USE_FSL 0U
#define XPAR_RUNTIME_KEYBOARD_SEND_FSL 0U
#define XPAR_RUNTIME_KEYBOARD_RECV_FSL 0U

#define XPAR_RUNTIME_SERIAL_OUT_DEVICE_ID 1U
#define XPAR_RUNTIME_SERIAL_OUT_BASEADDR 0xF1810000U
#define XPAR_RUNTIME_SERIAL_OUT_USE_FSL 0U
#define XPAR_RUNTIME_SERIAL_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_SERIAL_OUT_RECV_FSL 0U

#define XPAR_RUNTIME_RUNTIME1_DEVICE_ID 2U
#define XPAR_RUNTIME_RUNTIME1_BASEADDR 0xF0830000U
#define XPAR_RUNTIME_RUNTIME1_USE_FSL 0U
#define XPAR_RUNTIME_RUNTIME1_SEND_FSL 0U
#define XPAR_RUNTIME_RUNTIME1_RECV_FSL 0U

#define XPAR_RUNTIME_RUNTIME2_DEVICE_ID 3U
#define XPAR_RUNTIME_RUNTIME2_BASEADDR 0xF0850000U
#define XPAR_RUNTIME_RUNTIME2_USE_FSL 0U
#define XPAR_RUNTIME_RUNTIME2_SEND_FSL 0U
#define XPAR_RUNTIME_RUNTIME2_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_DATA_IN_DEVICE_ID 4U
#define XPAR_RUNTIME_STORAGE_DATA_IN_BASEADDR 0xF1830000U
#define XPAR_RUNTIME_STORAGE_DATA_IN_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_IN_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_IN_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_DATA_OUT_DEVICE_ID 5U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_BASEADDR 0xF1850000U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_CMD_IN_DEVICE_ID 6U
#define XPAR_RUNTIME_STORAGE_CMD_IN_BASEADDR 0xF1870000U
#define XPAR_RUNTIME_STORAGE_CMD_IN_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_IN_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_IN_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_CMD_OUT_DEVICE_ID 7U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_BASEADDR 0xF18A0000U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_RECV_FSL 0U

#define XPAR_RUNTIME_OS_DEVICE_ID 8U
#define XPAR_RUNTIME_OS_BASEADDR 0xF0810000U
#define XPAR_RUNTIME_OS_USE_FSL 0U
#define XPAR_RUNTIME_OS_SEND_FSL 0U
#define XPAR_RUNTIME_OS_RECV_FSL 0U

#define XPAR_RUNTIME_NETWORK_DATA_IN_DEVICE_ID 9U
#define XPAR_RUNTIME_NETWORK_DATA_IN_BASEADDR 0xF0870000
#define XPAR_RUNTIME_NETWORK_DATA_IN_USE_FSL 0U
#define XPAR_RUNTIME_NETWORK_DATA_IN_SEND_FSL 0U
#define XPAR_RUNTIME_NETWORK_DATA_IN_RECV_FSL 0U

#define XPAR_RUNTIME_NETWORK_DATA_OUT_DEVICE_ID 10U
#define XPAR_RUNTIME_NETWORK_DATA_OUT_BASEADDR 0xF0890000
#define XPAR_RUNTIME_NETWORK_DATA_OUT_USE_FSL 0U
#define XPAR_RUNTIME_NETWORK_DATA_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_NETWORK_DATA_OUT_RECV_FSL 0U

#define XPAR_RUNTIME_NETWORK_CMD_IN_DEVICE_ID 11U
#define XPAR_RUNTIME_NETWORK_CMD_IN_BASEADDR 0xF08C0000
#define XPAR_RUNTIME_NETWORK_CMD_IN_USE_FSL 0U
#define XPAR_RUNTIME_NETWORK_CMD_IN_SEND_FSL 0U
#define XPAR_RUNTIME_NETWORK_CMD_IN_RECV_FSL 0U

#define XPAR_RUNTIME_NETWORK_CMD_OUT_DEVICE_ID 12U
#define XPAR_RUNTIME_NETWORK_CMD_OUT_BASEADDR 0xF08E0000
#define XPAR_RUNTIME_NETWORK_CMD_OUT_USE_FSL 0U
#define XPAR_RUNTIME_NETWORK_CMD_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_NETWORK_CMD_OUT_RECV_FSL 0U

#elif RUNTIME_ID == 2
#define XPAR_RUNTIME_KEYBOARD_DEVICE_ID 0U
#define XPAR_RUNTIME_KEYBOARD_BASEADDR 0xF08E0000U
#define XPAR_RUNTIME_KEYBOARD_USE_FSL 0U
#define XPAR_RUNTIME_KEYBOARD_SEND_FSL 0U
#define XPAR_RUNTIME_KEYBOARD_RECV_FSL 0U

#define XPAR_RUNTIME_SERIAL_OUT_DEVICE_ID 1U
#define XPAR_RUNTIME_SERIAL_OUT_BASEADDR 0xF1800000U
#define XPAR_RUNTIME_SERIAL_OUT_USE_FSL 0U
#define XPAR_RUNTIME_SERIAL_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_SERIAL_OUT_RECV_FSL 0U

#define XPAR_RUNTIME_RUNTIME1_DEVICE_ID 2U
#define XPAR_RUNTIME_RUNTIME1_BASEADDR 0xF0800000U
#define XPAR_RUNTIME_RUNTIME1_USE_FSL 0U
#define XPAR_RUNTIME_RUNTIME1_SEND_FSL 0U
#define XPAR_RUNTIME_RUNTIME1_RECV_FSL 0U

#define XPAR_RUNTIME_RUNTIME2_DEVICE_ID 3U
#define XPAR_RUNTIME_RUNTIME2_BASEADDR 0xF0850000U
#define XPAR_RUNTIME_RUNTIME2_USE_FSL 0U
#define XPAR_RUNTIME_RUNTIME2_SEND_FSL 0U
#define XPAR_RUNTIME_RUNTIME2_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_DATA_IN_DEVICE_ID 4U
#define XPAR_RUNTIME_STORAGE_DATA_IN_BASEADDR 0xF1820000U
#define XPAR_RUNTIME_STORAGE_DATA_IN_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_IN_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_IN_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_DATA_OUT_DEVICE_ID 5U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_BASEADDR 0xF1840000U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_DATA_OUT_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_CMD_IN_DEVICE_ID 6U
#define XPAR_RUNTIME_STORAGE_CMD_IN_BASEADDR 0xF1860000U
#define XPAR_RUNTIME_STORAGE_CMD_IN_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_IN_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_IN_RECV_FSL 0U

#define XPAR_RUNTIME_STORAGE_CMD_OUT_DEVICE_ID 7U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_BASEADDR 0xF1880000U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_USE_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_STORAGE_CMD_OUT_RECV_FSL 0U

#define XPAR_RUNTIME_OS_DEVICE_ID 8U
#define XPAR_RUNTIME_OS_BASEADDR 0xF0820000U
#define XPAR_RUNTIME_OS_USE_FSL 0U
#define XPAR_RUNTIME_OS_SEND_FSL 0U
#define XPAR_RUNTIME_OS_RECV_FSL 0U

#define XPAR_RUNTIME_NETWORK_DATA_IN_DEVICE_ID 9U
#define XPAR_RUNTIME_NETWORK_DATA_IN_BASEADDR 0xF0870000
#define XPAR_RUNTIME_NETWORK_DATA_IN_USE_FSL 0U
#define XPAR_RUNTIME_NETWORK_DATA_IN_SEND_FSL 0U
#define XPAR_RUNTIME_NETWORK_DATA_IN_RECV_FSL 0U

#define XPAR_RUNTIME_NETWORK_DATA_OUT_DEVICE_ID 10U
#define XPAR_RUNTIME_NETWORK_DATA_OUT_BASEADDR 0xF0880000
#define XPAR_RUNTIME_NETWORK_DATA_OUT_USE_FSL 0U
#define XPAR_RUNTIME_NETWORK_DATA_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_NETWORK_DATA_OUT_RECV_FSL 0U

#define XPAR_RUNTIME_NETWORK_CMD_IN_DEVICE_ID 11U
#define XPAR_RUNTIME_NETWORK_CMD_IN_BASEADDR 0xF08B0000
#define XPAR_RUNTIME_NETWORK_CMD_IN_USE_FSL 0U
#define XPAR_RUNTIME_NETWORK_CMD_IN_SEND_FSL 0U
#define XPAR_RUNTIME_NETWORK_CMD_IN_RECV_FSL 0U

#define XPAR_RUNTIME_NETWORK_CMD_OUT_DEVICE_ID 12U
#define XPAR_RUNTIME_NETWORK_CMD_OUT_BASEADDR 0xF08D0000
#define XPAR_RUNTIME_NETWORK_CMD_OUT_USE_FSL 0U
#define XPAR_RUNTIME_NETWORK_CMD_OUT_SEND_FSL 0U
#define XPAR_RUNTIME_NETWORK_CMD_OUT_RECV_FSL 0U
#endif

/* mailboxs connected to Storage (Microblaze 4) */
#define XPAR_STORAGE_MBOX_DATA_IN_DEVICE_ID 0U
#define XPAR_STORAGE_MBOX_DATA_IN_BASEADDR 0xF0870000U
#define XPAR_STORAGE_MBOX_DATA_IN_USE_FSL 0U
#define XPAR_STORAGE_MBOX_DATA_IN_SEND_FSL 0U
#define XPAR_STORAGE_MBOX_DATA_IN_RECV_FSL 0U

#define XPAR_STORAGE_MBOX_DATA_OUT_DEVICE_ID 1U
#define XPAR_STORAGE_MBOX_DATA_OUT_BASEADDR 0xF0880000U
#define XPAR_STORAGE_MBOX_DATA_OUT_USE_FSL 0U
#define XPAR_STORAGE_MBOX_DATA_OUT_SEND_FSL 0U
#define XPAR_STORAGE_MBOX_DATA_OUT_RECV_FSL 0U

#define XPAR_STORAGE_MBOX_CMD_IN_DEVICE_ID 2U
#define XPAR_STORAGE_MBOX_CMD_IN_BASEADDR 0XF08A0000
#define XPAR_STORAGE_MBOX_CMD_IN_USE_FSL 0U
#define XPAR_STORAGE_MBOX_CMD_IN_SEND_FSL 0U
#define XPAR_STORAGE_MBOX_CMD_IN_RECV_FSL 0U

#define XPAR_STORAGE_MBOX_CMD_OUT_DEVICE_ID 3U
#define XPAR_STORAGE_MBOX_CMD_OUT_BASEADDR 0XF08D0000
#define XPAR_STORAGE_MBOX_CMD_OUT_USE_FSL 0U
#define XPAR_STORAGE_MBOX_CMD_OUT_SEND_FSL 0U
#define XPAR_STORAGE_MBOX_CMD_OUT_RECV_FSL 0U

/* mailboxs connected to Network (Microblaze 5) */
#define XPAR_NETWORK_MBOX_DATA_IN_DEVICE_ID 0U
#define XPAR_NETWORK_MBOX_DATA_IN_BASEADDR 0xF0890000
#define XPAR_NETWORK_MBOX_DATA_IN_USE_FSL 0U
#define XPAR_NETWORK_MBOX_DATA_IN_SEND_FSL 0U
#define XPAR_NETWORK_MBOX_DATA_IN_RECV_FSL 0U

#define XPAR_NETWORK_MBOX_DATA_OUT_DEVICE_ID 1U
#define XPAR_NETWORK_MBOX_DATA_OUT_BASEADDR 0xF08C0000
#define XPAR_NETWORK_MBOX_DATA_OUT_USE_FSL 0U
#define XPAR_NETWORK_MBOX_DATA_OUT_SEND_FSL 0U
#define XPAR_NETWORK_MBOX_DATA_OUT_RECV_FSL 0U

#define XPAR_NETWORK_MBOX_CMD_IN_DEVICE_ID 2U
#define XPAR_NETWORK_MBOX_CMD_IN_BASEADDR 0xF08D0000
#define XPAR_NETWORK_MBOX_CMD_IN_USE_FSL 0U
#define XPAR_NETWORK_MBOX_CMD_IN_SEND_FSL 0U
#define XPAR_NETWORK_MBOX_CMD_IN_RECV_FSL 0U

#define XPAR_NETWORK_MBOX_CMD_OUT_DEVICE_ID 3U
#define XPAR_NETWORK_MBOX_CMD_OUT_BASEADDR 0xF08F0000
#define XPAR_NETWORK_MBOX_CMD_OUT_USE_FSL 0U
#define XPAR_NETWORK_MBOX_CMD_OUT_SEND_FSL 0U
#define XPAR_NETWORK_MBOX_CMD_OUT_RECV_FSL 0U

#define XPAR_NETWORK_STORAGE_MBOX_DATA_OUT_DEVICE_ID 4U
#define XPAR_NETWORK_STORAGE_MBOX_DATA_OUT_BASEADDR 0xF1810000
#define XPAR_NETWORK_STORAGE_MBOX_DATA_OUT_USE_FSL 0U
#define XPAR_NETWORK_STORAGE_MBOX_DATA_OUT_SEND_FSL 0U
#define XPAR_NETWORK_STORAGE_MBOX_DATA_OUT_RECV_FSL 0U

/* mailboxs connected to OS (Microblaze 6) */
#define XPAR_OS_MBOX_Q_KEYBOARD_DEVICE_ID 0U
#define XPAR_OS_MBOX_Q_KEYBOARD_BASEADDR 0xF1850000U
#define XPAR_OS_MBOX_Q_KEYBOARD_USE_FSL 0U
#define XPAR_OS_MBOX_Q_KEYBOARD_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_KEYBOARD_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_SERIAL_OUT_DEVICE_ID 1U
#define XPAR_OS_MBOX_Q_SERIAL_OUT_BASEADDR 0xF1860000U
#define XPAR_OS_MBOX_Q_SERIAL_OUT_USE_FSL 0U
#define XPAR_OS_MBOX_Q_SERIAL_OUT_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_SERIAL_OUT_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_RUNTIME1_DEVICE_ID 2U
#define XPAR_OS_MBOX_Q_RUNTIME1_BASEADDR 0xF0810000U
#define XPAR_OS_MBOX_Q_RUNTIME1_USE_FSL 0U
#define XPAR_OS_MBOX_Q_RUNTIME1_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_RUNTIME1_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_RUNTIME2_DEVICE_ID 3U
#define XPAR_OS_MBOX_Q_RUNTIME2_BASEADDR 0xF0850000U
#define XPAR_OS_MBOX_Q_RUNTIME2_USE_FSL 0U
#define XPAR_OS_MBOX_Q_RUNTIME2_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_RUNTIME2_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_STORAGE_DATA_IN_DEVICE_ID 4U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_IN_BASEADDR 0xF1880000U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_IN_USE_FSL 0U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_IN_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_IN_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_DEVICE_ID 5U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_BASEADDR 0xF18B0000U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_USE_FSL 0U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_STORAGE_DATA_OUT_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_CMD_IN_DEVICE_ID 6U
#define XPAR_OS_MBOX_Q_CMD_IN_BASEADDR 0xF18C0000U
#define XPAR_OS_MBOX_Q_CMD_IN_USE_FSL 0U
#define XPAR_OS_MBOX_Q_CMD_IN_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_CMD_IN_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_CMD_OUT_DEVICE_ID 7U
#define XPAR_OS_MBOX_Q_CMD_OUT_BASEADDR 0xF18E0000U
#define XPAR_OS_MBOX_Q_CMD_OUT_USE_FSL 0U
#define XPAR_OS_MBOX_Q_CMD_OUT_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_CMD_OUT_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_ENCLAVE0_DEVICE_ID 8U
#define XPAR_OS_MBOX_Q_ENCLAVE0_BASEADDR 0xF0800000U
#define XPAR_OS_MBOX_Q_ENCLAVE0_USE_FSL 0U
#define XPAR_OS_MBOX_Q_ENCLAVE0_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_ENCLAVE0_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_ENCLAVE1_DEVICE_ID 9U
#define XPAR_OS_MBOX_Q_ENCLAVE1_BASEADDR 0xF0830000U
#define XPAR_OS_MBOX_Q_ENCLAVE1_USE_FSL 0U
#define XPAR_OS_MBOX_Q_ENCLAVE1_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_ENCLAVE1_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_UNTRUSTED_DEVICE_ID 10
#define XPAR_OS_MBOX_Q_UNTRUSTED_BASEADDR 0xF1830000U
#define XPAR_OS_MBOX_Q_UNTRUSTED_USE_FSL 0U
#define XPAR_OS_MBOX_Q_UNTRUSTED_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_UNTRUSTED_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_OSU_DEVICE_ID 11
#define XPAR_OS_MBOX_Q_OSU_BASEADDR 0xF1820000U
#define XPAR_OS_MBOX_Q_OSU_USE_FSL 0U
#define XPAR_OS_MBOX_Q_OSU_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_OSU_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_NETWORK_DATA_IN_DEVICE_ID 12U
#define XPAR_OS_MBOX_Q_NETWORK_DATA_IN_BASEADDR 0xF0860000
#define XPAR_OS_MBOX_Q_NETWORK_DATA_IN_USE_FSL 0U
#define XPAR_OS_MBOX_Q_NETWORK_DATA_IN_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_NETWORK_DATA_IN_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_NETWORK_DATA_OUT_DEVICE_ID 13U
#define XPAR_OS_MBOX_Q_NETWORK_DATA_OUT_BASEADDR 0xF0880000
#define XPAR_OS_MBOX_Q_NETWORK_DATA_OUT_USE_FSL 0U
#define XPAR_OS_MBOX_Q_NETWORK_DATA_OUT_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_NETWORK_DATA_OUT_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_NETWORK_CMD_IN_DEVICE_ID 14U
#define XPAR_OS_MBOX_Q_NETWORK_CMD_IN_BASEADDR 0xF08B0000
#define XPAR_OS_MBOX_Q_NETWORK_CMD_IN_USE_FSL 0U
#define XPAR_OS_MBOX_Q_NETWORK_CMD_IN_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_NETWORK_CMD_IN_RECV_FSL 0U

#define XPAR_OS_MBOX_Q_NETWORK_CMD_OUT_DEVICE_ID 15U
#define XPAR_OS_MBOX_Q_NETWORK_CMD_OUT_BASEADDR 0xF08D0000
#define XPAR_OS_MBOX_Q_NETWORK_CMD_OUT_USE_FSL 0U
#define XPAR_OS_MBOX_Q_NETWORK_CMD_OUT_SEND_FSL 0U
#define XPAR_OS_MBOX_Q_NETWORK_CMD_OUT_RECV_FSL 0U

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
