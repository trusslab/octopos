/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
/* OctopOS bluetooth code */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <arch/mailbox_bluetooth.h>
#include <octopos/mailbox.h>
#include <octopos/io.h>
#include <octopos/bluetooth.h>
#include <octopos/error.h>
#include <tpm/hash.h>
#include <tpm/tpm.h>
#include <tpm/rsa.h>

uint8_t bound = 0;
uint8_t used = 0;
uint8_t authenticated = 0;

/* BD_ADDR for a few devices (resources). */
#define NUM_RESOURCES	2
uint8_t devices[NUM_RESOURCES][BD_ADDR_LEN] = {
					{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc},
					{0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21}};

int bound_devices[NUM_RESOURCES] = {0, 0};

/* We use the array index as the logical address. */
#define GLUCOSE_MONITOR_AM_ADDR		0
#define INSULIN_PUMP_AM_ADDR		1

/* FIXME: move somewhere else */
char glucose_monitor_password[32] = "glucose_monitor_password";
int glucose_monitor_authenticated = 0;

unsigned char admin_public_key[] =
"-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwWFcfENwpIqWp3spCLTg\n"\
"XncdEG4eBQQK6YV4cvX//b2ab8rkwo+xmLD0lGqpFrtWHAvtiI5fqh5jPHZwrd54\n"\
"1bIXcrJOrhhAJGiEW/i/aQB/XQyFWDWt/+wr6SE7J5KZEHZpVxsSeu9yuIWDSYTp\n"\
"cOk674/leUjIpPpxZkbHVQe0R/Dja1Xi5SRnyeuYX7fSV2mDNltZ3sCuCXyVNgJ1\n"\
"wtFGZj87NCHw7vbPJxI8hb2ro3REbUUzfeB0A+tizU54MkCot50iqgX0C3TLavC4\n"\
"UysSb22EZY89zS6eZ174Lru4XYEIpStT6IzurmvLbU2AECkkRNlJBc6e+jMR8z34\n"\
"cQIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

/* FIXME: ugly. */
/* FIXME: duplicate in runtime/runtime.c */
static int set_btp_am_addr(struct btpacket *btp, uint8_t am_addr)
{
	switch(am_addr) {
	case 0:
		btp->header1.am_addr = 0;
		return 0;
	case 1:
		btp->header1.am_addr = 1;
		return 0;
	case 2:
		btp->header1.am_addr = 2;
		return 0;
	case 3:
		btp->header1.am_addr = 3;
		return 0;
	case 4:
		btp->header1.am_addr = 4;
		return 0;
	case 5:
		btp->header1.am_addr = 5;
		return 0;
	case 6:
		btp->header1.am_addr = 6;
		return 0;
	case 7:
		btp->header1.am_addr = 7;
		return 0;
	default:
		return ERR_INVALID;
	}
}

static void glucose_monitor_func(struct btpacket *btp)
{
	uint8_t buf_large[MAILBOX_QUEUE_MSG_SIZE_LARGE];
	struct btpacket *btp2 = (struct btpacket *) buf_large;
	
	memset(buf_large, 0x0, MAILBOX_QUEUE_MSG_SIZE_LARGE);
	set_btp_am_addr(btp2, GLUCOSE_MONITOR_AM_ADDR);

	if (!glucose_monitor_authenticated) {
		if (!strcmp((char *) btp->data, glucose_monitor_password)) {
			glucose_monitor_authenticated = 1;
			printf("glucose_monitor successfully authenticated.\n");
			btp2->data[0] = 1; /* success */
			write_to_bluetooth_data_queue(buf_large);
		} else {
			printf("glucose_monitor authentication failed.\n");
			btp2->data[0] = 0; /* failure */
			write_to_bluetooth_data_queue(buf_large);
		}

		return;
	}

	if (btp->data[0] == 1) {
		/* Request a measurement */
		srand(time(NULL));
		uint16_t measurement = (rand() % 300) + 100; /* in mg/dL */
		printf("glucose_monitor: measurement = %d.\n", measurement);
		printf("glucose_monitor: sending a response.\n");

		btp2->data[0] = 1; /* success */
		*((uint16_t *) &btp2->data[1]) = measurement;
		write_to_bluetooth_data_queue(buf_large);

		return;
	} else if (btp->data[0] == 0) {
		/* Terminate session */
		glucose_monitor_authenticated = 0;
		printf("glucose_monitor deauthenticated.\n");
		btp2->data[0] = 1; /* success */
		write_to_bluetooth_data_queue(buf_large);
		return;
	} else {
		printf("glucose_monitor received an invalid message.\n");
		btp2->data[0] = 0; /* failure */
		write_to_bluetooth_data_queue(buf_large);
	}
}

/* FIXME: move somewhere else */
char insulin_pump_password[32] = "insulin_pump_password";
int insulin_pump_authenticated = 0;

static void insulin_pump_func(struct btpacket *btp)
{
	uint8_t buf_large[MAILBOX_QUEUE_MSG_SIZE_LARGE];
	struct btpacket *btp2 = (struct btpacket *) buf_large;
	
	memset(buf_large, 0x0, MAILBOX_QUEUE_MSG_SIZE_LARGE);
	set_btp_am_addr(btp2, INSULIN_PUMP_AM_ADDR);

	if (!insulin_pump_authenticated) {
		if (!strcmp((char *) btp->data, insulin_pump_password)) {
			insulin_pump_authenticated = 1;
			printf("insulin_pump successfully authenticated.\n");
			btp2->data[0] = 1; /* success */
			write_to_bluetooth_data_queue(buf_large);
		} else {
			printf("insulin_pump authentication failed.\n");
			btp2->data[0] = 0; /* failure */
			write_to_bluetooth_data_queue(buf_large);
		}

		return;
	}

	if (btp->data[0] == 1) {
		/* Request an injection */
		uint8_t dose = btp->data[1];
		printf("insulin_pump: adminstering %d doses of insulin.\n",
		       dose);
		printf("insulin_pump: sending a response.\n");

		btp2->data[0] = 1; /* success */
		write_to_bluetooth_data_queue(buf_large);

		return;
	} else if (btp->data[0] == 0) {
		/* Terminate session */
		insulin_pump_authenticated = 0;
		printf("insulin_pump deauthenticated.\n");
		btp2->data[0] = 1; /* success */
		write_to_bluetooth_data_queue(buf_large);
		return;
	} else {
		printf("insulin_pump received an invalid message.\n");
		btp2->data[0] = 0; /* failure */
		write_to_bluetooth_data_queue(buf_large);
	}
}

void (*device_funcs[NUM_RESOURCES])(struct btpacket *btp) =
				{glucose_monitor_func, insulin_pump_func};

/*
 * Return error if bound, used, or authenticated is set.
 * Return error if invalid resource name
 * Bind the resource to the data queues.
 * Set the global var "bound"
 * This is irreversible until reset.
 *
 * We don't use authentication for Bluetooth.
 */
static void bluetooth_bind_resource(uint8_t *buf)
{
	uint8_t am_addrs[NUM_RESOURCES];
	uint32_t num_matched = 0;

	/* am_addr value of 0xFF is invalid */
	memset(am_addrs, 0xFF, NUM_RESOURCES);

	if (bound || used || authenticated) {
		printf("Error: %s: the bind op is invalid if bound (%d), "
		       "used (%d), or authenticated (%d) is set.\n", __func__,
		       bound, used, authenticated);
		char dummy;
		BLUETOOTH_SET_ONE_RET_DATA(ERR_INVALID, &dummy, 0)
		return;
	}

	BLUETOOTH_GET_ONE_ARG_DATA

	/* arg0 is the number of resources that need to be bound */
	if (arg0 < 1 || arg0 > NUM_RESOURCES) {
		printf("Error: %s: invalid number of resources to be bound "
		       "(%d)\n", __func__, arg0);
		char dummy;
		BLUETOOTH_SET_ONE_RET_DATA(ERR_INVALID, &dummy, 0)
		return;
	}

	if (_size != (arg0 * BD_ADDR_LEN)) {
		printf("Error: %s: invalid device_name(s) size (%d)\n",
		       __func__, (int) _size);
		char dummy;
		BLUETOOTH_SET_ONE_RET_DATA(ERR_INVALID, &dummy, 0)
		return;
	}

	for (int i = 0; i < (int) arg0; i++) {
		am_addrs[i] = 0; /* not found */
		for (int j = 0; j < NUM_RESOURCES; j++) {
			if (!memcmp(data + (i * BD_ADDR_LEN),
				    devices[j], BD_ADDR_LEN)) {
				num_matched++;
				bound_devices[j] = 1; 
				am_addrs[i] = j;
			}
		}
	}

	if (num_matched != arg0) {
		printf("Error: %s: could %s find %d of the %d "
		       "requested devices.\n", __func__,
		       num_matched ? "only" : "", num_matched, arg0);
		for (int i = 0; i < NUM_RESOURCES; i++) {
			bound_devices[i] = 0;
			am_addrs[i] = 0xFF;
		}

		char dummy;
		BLUETOOTH_SET_ONE_RET_DATA(ERR_FOUND, &dummy, 0)
		return;
	}

	bound = 1;

	BLUETOOTH_SET_ONE_RET_DATA(0, am_addrs, arg0)
}

/*
 * Bound or not?
 * Used or not?
 * If authentication is needed, is it authenticated?
 * If bound, resource name size and then resouce name.
 * Other device specific info:
 *	network packet header
 * If global flag "used" not set, set it.
 * This is irreversible until reset.
 */
static void bluetooth_query_state(uint8_t *buf)
{
	uint8_t state[4 + (BD_ADDR_LEN * NUM_RESOURCES)];
	uint32_t state_size = 3;

	state[0] = bound;
	state[1] = used;
	used = 1;

	state[2] = authenticated;

	if (bound) {
		int num_bound_devices = 0;
		for (int i = 0; i < NUM_RESOURCES; i++) {
			if (!bound_devices[i])
				continue;

			memcpy(&state[4 + (num_bound_devices * (BD_ADDR_LEN + 1))],
			       devices[i], BD_ADDR_LEN);
			/* am_addr */
			state[4 + (num_bound_devices * (BD_ADDR_LEN + 1)) +
			      BD_ADDR_LEN ] = i;
			num_bound_devices++;
			state_size += (BD_ADDR_LEN + 1);
		}
		state[3] = num_bound_devices;
		state_size++;
	}

	BLUETOOTH_SET_ONE_RET_DATA(0, state, state_size)
}

/*
 * Return error if "bound" not set.
 * Return error if authentication is needed and not authenticated. 
 * Return error if bound resource not created (destroyed).
 * If global flag "used" not set, set it.
 * This is irreversible until reset.
 * Process incoming data on data queue (one or multiple).
 */
static void bluetooth_send_data(uint8_t *buf)
{
	uint8_t buf_large[MAILBOX_QUEUE_MSG_SIZE_LARGE];
	struct btpacket *btp = (struct btpacket *) buf_large;
	uint8_t am_addr;

	if (!bound || !authenticated) {
		printf("Error: %s: the send data op is invalid if bound (%d) "
		       "or authenticated (%d) is not set.\n", __func__,
		       bound, authenticated);
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
		return;
	}

	used = 1;

	BLUETOOTH_GET_ONE_ARG

	if (arg0 != 1) {
		printf("Error: %s: only supports sending one packet.\n",
		       __func__);
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
		return;
	}

	read_from_bluetooth_data_queue(buf_large);

	am_addr = (uint8_t) btp->header1.am_addr;	
	if (am_addr >= NUM_RESOURCES) {
		printf("Error: %s: invalid am_addr (%d).\n", __func__, am_addr);
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
		return;
	}

	if (!bound_devices[am_addr]) {
		printf("Error: %s: device %d not bound\n", __func__, am_addr);
		BLUETOOTH_SET_ONE_RET(ERR_PERMISSION)
		return;
	}

	(*device_funcs[am_addr])(btp);

	BLUETOOTH_SET_ONE_RET(0)
}

static int check_signature(uint8_t *signature, uint8_t proc_id)
{
	int ret;
	uint8_t tpm_pcr[TPM_EXTEND_HASH_SIZE];
	uint8_t expected_pcr[TPM_EXTEND_HASH_SIZE];

	/* Retrieve proc's PCR value. */
	ret = tpm_processor_read_pcr(PROC_TO_PCR(proc_id), tpm_pcr);
	if (ret) {
		printf("Error: %s: couldn't read TPM PCR for proc %d.\n",
		       __func__, proc_id);
		return ERR_FAULT;
	}

	/* Decrypt signature to get the expected PCR val. */
	ret = public_decrypt((unsigned char *) signature, RSA_SIGNATURE_SIZE,
			     admin_public_key, expected_pcr);
	if (ret != TPM_EXTEND_HASH_SIZE) {
		printf("Error: %s: couldn't decrypt the signature (%d).\n",
		       __func__, ret);
		return ERR_FAULT;
	}

	ret = memcmp(tpm_pcr, expected_pcr, TPM_EXTEND_HASH_SIZE);
	if (ret) {
		printf("Error: %s: retrieved and expected PCR vals don't "
		       "match.\n", __func__);
		return ERR_INVALID;
	}

	return 0;
}

/*
 * Used when resource needs authentication.
 * Return error if "bound" not set.
 * Return error if "authenticated" already set.
 * "authenticated" global variable will be set on success
 * If global flag "used" not set, set it.
 * This is irreversible until reset.
 * May require/receive signature for the TPM measurement (bluetooth service does)
 *
 * @proc_id: ID of the requesting processor.
 */
static void bluetooth_authenticate(uint8_t *buf, uint8_t proc_id)
{
	int ret;
	uint8_t _buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t signature[RSA_SIGNATURE_SIZE];
	uint32_t remaining_size = RSA_SIGNATURE_SIZE;
	uint32_t msg_size = MAILBOX_QUEUE_MSG_SIZE;
	uint32_t offset = 0;
	uint8_t _proc_id;

	used = 1;

	/* receive signature */
	while (remaining_size) {
		if (remaining_size < msg_size)
			msg_size = remaining_size;

		_proc_id = read_from_bluetooth_cmd_queue_get_owner(_buf);

		if (_proc_id != proc_id) {
			printf("Error: %s: unexpected proc_id for the sender "
			       "of the message (%d, %d).\n", __func__, proc_id,
			       _proc_id);
			BLUETOOTH_SET_ONE_RET(ERR_UNEXPECTED)
			return;
		}

		memcpy(signature + offset, _buf, msg_size); 

		if (remaining_size >= msg_size)
			remaining_size -= msg_size;
		else
			remaining_size = 0;

		offset += msg_size;
	}

	if (!bound) {
		printf("Error: %s: no bound device(s)\n", __func__);
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
		return;
	}

	if (authenticated) {
		printf("Error: %s: already authenticated.\n", __func__);
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
		return;
	}

	ret = check_signature(signature, proc_id);
	if (ret) {
		printf("Error: %s: authentication failed\n",__func__);
		BLUETOOTH_SET_ONE_RET(ERR_PERMISSION)
		return;
	}			

	authenticated = 1;

	BLUETOOTH_SET_ONE_RET(0)
}

/*
 * Return error if "bound" not set.
 * Return error if "authenticated" not set.
 * "authenticated" global variable will be unset.
 * If global flag "used" not set, set it.
 * This is irreversible until rest.
 */
static void bluetooth_deauthenticate(uint8_t *buf)
{
	used = 1;

	if (!bound || !authenticated) {
		printf("Error: %s: the deauthenticate op is invalid if bound "
		       "(%d) or authenticated (%d) is not set.\n", __func__,
		       bound, authenticated);
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
		return;
	}

	authenticated = 0;	
		
	BLUETOOTH_SET_ONE_RET(0)
}

static void process_cmd(uint8_t *buf, uint8_t proc_id)
{
	switch (buf[0]) {
	case IO_OP_QUERY_ALL_RESOURCES:
		/* 
		 * List available resources.
		 * Not usable if resource bound
		 * If authentication is used, return keys (i.e., TPM
		 * measurements) for resources.
		 * Can be implemented to return all data in one response or in
		 * separate queries.
		 */

		/* Not implemented for now */
		printf("Error: %s: list_resources op not implemented by the "
		       "Bluetooth service (yet)\n", __func__);
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
		break;

	case IO_OP_CREATE_RESOURCE:
		/* Create a new resource
		 * Not usable if any resource is bound
		 * Non-persistent resources deleted upon reset.
		 * Persistent ones need a method to be destroyed, e.g.,
		 * an explicit call or a time-out.
		 * Receives TPM measurement if resource needs authentication
		 */
		/* No op for Bluetooth */
		printf("Error: %s: create_resource op not supported by the "
		       "Bluetooth service\n", __func__);
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
		break;

	case IO_OP_BIND_RESOURCE:
		bluetooth_bind_resource(buf);		
		break;


	case IO_OP_QUERY_STATE:
		bluetooth_query_state(buf);
		break;

	case IO_OP_AUTHENTICATE:
		bluetooth_authenticate(buf, proc_id);
		break;

	case IO_OP_SEND_DATA:
		bluetooth_send_data(buf);
		break;

	case IO_OP_RECEIVE_DATA:
		/*
		 * Return error if "bound" not set.
		 * Return error if authentication is needed and not authenticated. 
		 * Return error if bound resource not created (destroyed).
		 * If global flag "used" not set, set it.
		 * This is irreversible until reset.
		 * Process incoming data on data queue (one or multiple).
		 */ 

		/* No op for bluetooth */
		printf("Error: %s: receive_data op not supported by the "
		       "Bluetooth service\n", __func__);
		used = 1;
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
		break;

	case IO_OP_DEAUTHENTICATE:
		bluetooth_deauthenticate(buf);
		break;

	case IO_OP_DESTROY_RESOURCE:
		/*
		 * Return error if "bound" not set.
		 * Return error if authentication is needed and not authenticated. 
		 * If global flag "used" not set, set it.
		 * This is irreversible until reset.
		 * Destroy resource(s).
		 * After a resource is destroyed, it cannot be used.
		 * Deauthenticate if needed.
		 */ 

		/* No op for bluetooth */
		printf("Error: %s: destroy_resource op not supported by the "
		       "Bluetooth service\n", __func__);
		used = 1;
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
		break;

	default:
		/*
		 * If global flag "used" not set, set it.
		 * This is irreversible until reset.
		 */
		printf("Error: %s: unknown op (%d)\n", __func__, buf[0]);
		used = 1;
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
		break;
	}
}

static int bluetooth_core(void)
{
	uint8_t buf[MAILBOX_QUEUE_MSG_SIZE];
	uint8_t proc_id;

	while (1) {
		proc_id = read_from_bluetooth_cmd_queue_get_owner(buf);
		process_cmd(buf, proc_id);
		write_to_bluetooth_cmd_queue(buf);
	}

	return 0;
}

int main(int argc, char **argv)
{
	/* Non-buffering stdout */
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("%s: bluetooth init\n", __func__);

	/* Need to make sure msgs are big enough so that we don't overflow
	 * when processing incoming msgs and preparing outgoing ones.
	 */
	/* FIXME: find the smallest bound. 64 is conservative. */
	if (MAILBOX_QUEUE_MSG_SIZE < 64) {
		printf("Error: %s: MAILBOX_QUEUE_MSG_SIZE is too small (%d).\n",
		       __func__, MAILBOX_QUEUE_MSG_SIZE);
		return -1;
	}

	int ret = init_bluetooth();
	if (ret)
		return ret;

	bluetooth_core();

	close_bluetooth();
}	
