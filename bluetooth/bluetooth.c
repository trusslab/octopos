/* OctopOS bluetooth code */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arch/mailbox_bluetooth.h>
#include <octopos/mailbox.h>
#include <octopos/io.h>
#include <octopos/bluetooth.h>
#include <octopos/error.h>

uint8_t bound = 0;
uint8_t used = 0;

/* BD_ADDR for a few devices (resources). */
#define NUM_RESOURCES	2
/* index 0 is dummy */
uint8_t devices[NUM_RESOURCES + 1][BD_ADDR_LEN] = {
					{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
					{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc},
					{0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21}};
int bound_device_index = 0;

void (*bound_device_func)(struct btpacket *btp) = NULL;

/* FIXME: move somewhere else */
char device1_password[32] = "Dev1Password";
int device1_authenticated = 0;

static void device1_func(struct btpacket *btp)
{
	if (!device1_authenticated) {
		if (!strcmp((char *) btp->data, device1_password)) {
			device1_authenticated = 1;
			printf("Device1 successfully authenticated.\n");
		} else {
			printf("Device1 authentication failed.\n");
		}

		return;
	}

	if (btp->data[0] == 1) {
		uint8_t buf_large[MAILBOX_QUEUE_MSG_SIZE_LARGE];
		struct btpacket *btp2 = (struct btpacket *) buf_large;
		printf("Device1: sending a response.\n");

		strcpy((char *) btp2->data, "Success!");
		write_to_bluetooth_data_queue(buf_large);

		return;
	} else if (btp->data[0] == 0) {
		device1_authenticated = 1;
		printf("Device1 deauthenticated.\n");
		return;
	}

	printf("Device1 received an invalid message.\n");
}

/* FIXME: move somewhere else */
char device2_password[32] = "Dev2Password";
int device2_authenticated = 0;

static void device2_func(struct btpacket *btp)
{
	printf("%s: received packet: %d\n", __func__, (uint8_t) btp->data[0]);
}

static void process_cmd(uint8_t *buf)
{
	switch (buf[0]) {
	case IO_OP_BIND_RESOURCE: {
		/* Return error if bound, used, or authenticated is set.
		 * Return error if invalid resource name
		 * Bind the resource to the data queues.
		 * Set the global var "bound"
		 * This is irreversible until reset.
		 */

		/* We don't use authentication for Bluetooth */

		if (bound || used) {
			printf("Error: %s: the bind op is invalid if bound (%d) "
			       "or used (%d) is set.\n", __func__, bound, used);
			BLUETOOTH_SET_ONE_RET(ERR_INVALID)
			break;
		}

		BLUETOOTH_GET_ZERO_ARGS_DATA
		if (_size != BD_ADDR_LEN) {
			printf("Error: %s: invalid device_name size (%d)\n",
			       __func__, (int) _size);
			BLUETOOTH_SET_ONE_RET(ERR_INVALID)
			break;
		}

		for (int i = 1; i <= NUM_RESOURCES; i++) {
			if (!memcmp(data, devices[i], BD_ADDR_LEN)) {
				bound_device_index = i;
				bound = 1;
				/* FIXME: not scalable */
				if (i == 1)
					bound_device_func = device1_func;
				else if (i == 2)
					bound_device_func = device2_func;
				break;
			}
		}

		if (!bound) {
			printf("Error: %s: resource ID for the bind op not "
			       "found.\n", __func__);
			BLUETOOTH_SET_ONE_RET(ERR_FOUND)
			break;
		}

		BLUETOOTH_SET_ONE_RET(0)
		break;
	}

	case IO_OP_CREATE_RESOURCE:
		/* Create a new resource
		 * Not usable if resource bound
		 * Non-persistent resources deleted upon reset.
		 * Persistent ones need a time-out.
		 * Can provide TPM measurements if resource needs authentication
		 */

		/* No op for Bluetooth */
		printf("Error: %s: create_resource op not supported by the "
		       "Bluetooth service\n", __func__);
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
		break;

	case IO_OP_QUERY_ALL_RESOURCES:
		/* List available resources.
		 * Not usable if resource bound
		 */

		/* Not implemented for now */
		printf("Error: %s: list_resources op not implemented by the "
		       "Bluetooth service (yet)\n", __func__);
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
		break;

	case IO_OP_QUERY_STATE: {
		/*
		 * Bound or not?
		 * Used or not?
		 * If authentication is needed, is it authenticated?
		 * If bound, resource name size and then resouce name.
		 * TPM quote.
		 * Other device specific info:
		 *	network packet header
		 */

		uint8_t state[3 + BD_ADDR_LEN];
		uint32_t state_size = 2;

		state[0] = bound;
		state[1] = used;
		if (bound) {
			state[2] = BD_ADDR_LEN;
			memcpy(&state[3], devices[bound_device_index],
			       BD_ADDR_LEN);
			state_size += (BD_ADDR_LEN + 1);
		}

		BLUETOOTH_SET_ONE_RET_DATA(0, state, state_size)
		break;
	}

	case IO_OP_AUTHENTICATE:
		/*
		 * Used when resource needs authentication.
		 * If needed, TPM quote need to be sent for authentication.
		 * "authenticated" global variable will be set on success
		 */

		/* No op for Bluetooth */
		printf("Error: %s: authenticate op not supported by the "
		       "Bluetooth service\n", __func__);
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
		break;

	case IO_OP_SEND_DATA: {
		/*
		 * Return error if "bound" not set.
		 * Return error if authentication is needed and not authenticated. 
		 * If global flag "used" not set, set it.
		 * This is irreversible until reset.
		 * Process incoming data on data queue (one or multiple).
		 */
		uint8_t buf_large[MAILBOX_QUEUE_MSG_SIZE_LARGE];
		struct btpacket *btp = (struct btpacket *) buf_large;

		if (!bound) {
			printf("Error: %s: no device is bound.\n", __func__);
			BLUETOOTH_SET_ONE_RET(ERR_INVALID)
			break;
		}

		used = 1;

		BLUETOOTH_GET_ONE_ARG

		if (arg0 != 1) {
			printf("Error: %s: only supports sending one packet.\n",
			       __func__);
			BLUETOOTH_SET_ONE_RET(ERR_INVALID)
			break;
		}

		read_from_bluetooth_data_queue(buf_large);

		if (bound_device_func)
			(*bound_device_func)(btp);

		BLUETOOTH_SET_ONE_RET(0)
		break;
	}

	case IO_OP_RECEIVE_DATA:
		/*
		 * Return error if "bound" not set.
		 * Return error if authentication is needed and not authenticated. 
		 * If global flag "used" not set, set it.
		 * This is irreversible until reset.
		 * Process incoming data on data queue (one or multiple).
		 */ 

		/* No op for bluetooth */
		printf("Error: %s: receive_data op not supported by the "
		       "Bluetooth service\n", __func__);
		BLUETOOTH_SET_ONE_RET(ERR_INVALID)
		break;

	default:
		printf("Error: %s: unknown op (%d)\n", __func__, buf[0]);
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
