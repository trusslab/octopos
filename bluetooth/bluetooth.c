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

uint8_t bound = 0;
uint8_t used = 0;

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

	if (bound || used) {
		printf("Error: %s: the bind op is invalid if bound (%d) "
		       "or used (%d) is set.\n", __func__, bound, used);
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
	uint8_t state[3 + (BD_ADDR_LEN * NUM_RESOURCES)];
	uint32_t state_size = 2;

	state[0] = bound;
	state[1] = used;
	used = 1;
	if (bound) {
		int num_bound_devices = 0;
		for (int i = 0; i < NUM_RESOURCES; i++) {
			if (!bound_devices[i])
				continue;

			memcpy(&state[3 + (num_bound_devices * (BD_ADDR_LEN + 1))],
			       devices[i], BD_ADDR_LEN);
			/* am_addr */
			state[3 + (num_bound_devices * (BD_ADDR_LEN + 1)) +
			      BD_ADDR_LEN ] = i;
			num_bound_devices++;
			state_size += (BD_ADDR_LEN + 1);
		}
		state[2] = num_bound_devices;
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

	if (!bound) {
		printf("Error: %s: no device is bound.\n", __func__);
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

static void process_cmd(uint8_t *buf)
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
		/*
		 * Used when resource needs authentication.
		 * Return error if "bound" not set.
		 * Return error if "authenticated" already set.
		 * "authenticated" global variable will be set on success
		 * If global flag "used" not set, set it.
		 * This is irreversible until reset.
		 */

		/* No op for Bluetooth */
		printf("Error: %s: authenticate op not supported by the "
		       "Bluetooth service\n", __func__);
		used = 1;
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
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
		/*
		 * Return error if "bound" not set.
		 * Return error if "authenticated" not set.
		 * "authenticated" global variable will be unset.
		 * If global flag "used" not set, set it.
		 * This is irreversible until rest.
		 */

		/* No op for Bluetooth */
		printf("Error: %s: deauthenticate op not supported by the "
		       "Bluetooth service\n", __func__);
		used = 1;
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
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

	while (1) {
		read_from_bluetooth_cmd_queue(buf);
		process_cmd(buf);
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
