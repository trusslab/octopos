#ifndef ARCH_SEC_HW

/* health_client app
 *
 * Based on:
 * bank_client.c
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#define APPLICATION
#include <octopos/mailbox.h>
#include <octopos/runtime.h>
#include <octopos/storage.h>
#include <octopos/bluetooth.h>
#include <octopos/tpm.h>
#include <network/sock.h>
#include <network/socket.h>
#include <tpm/hash.h>

/* Must be smaller than each message size minus 1.
 * For secure print, the message is the same as the mailbox size.
 * For insecure_printf, it's the mailbox size minus 3.
 */
#define MAX_CHARS_PER_MESSAGE		(MAILBOX_QUEUE_MSG_SIZE - 4)
#define MAX_PRINT_SIZE			((MAILBOX_QUEUE_MSG_SIZE - 4) * 20)
char output_buf_full[MAX_PRINT_SIZE];
char output_buf[MAILBOX_QUEUE_MSG_SIZE];
int num_chars = 0;
int msg_num = 0;

uint8_t glucose_monitor[BD_ADDR_LEN] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
uint8_t insulin_pump[BD_ADDR_LEN] = {0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21};

uint8_t network_pcr[TPM_EXTEND_HASH_SIZE];
uint8_t measured_network_pcr[TPM_EXTEND_HASH_SIZE];
uint8_t storage_pcr[TPM_EXTEND_HASH_SIZE];
uint8_t measured_storage_pcr[TPM_EXTEND_HASH_SIZE];
int trustworthy_storage_service = 0;

#define CONTEXT_SIGNATURE_SIZE	4
/* Used to check if context returned from storage is valid or junk */
uint8_t expected_context_signature[CONTEXT_SIGNATURE_SIZE] =
						{0x32, 0x9f, 0x33, 0x71};

struct app_context {
	uint8_t signature[CONTEXT_SIGNATURE_SIZE];
	uint8_t glucose_monitor_password[32];
	uint8_t insulin_pump_password[32];
	uint8_t bluetooth_pcr[TPM_EXTEND_HASH_SIZE];
	uint16_t glucose_measurement_avg;
	uint64_t last_measurement_time; /* in seconds compared to a ref. time */
};

struct app_context context;

#define loop_printf(print_cmd, fmt, args...) {				\
	memset(output_buf_full, 0x0, MAX_PRINT_SIZE);			\
	memset(output_buf, 0x0, MAILBOX_QUEUE_MSG_SIZE);		\
	num_chars = sprintf(output_buf_full, fmt, ##args);		\
	if (num_chars > MAX_PRINT_SIZE)					\
		num_chars = MAX_PRINT_SIZE;				\
	msg_num = 0;							\
	while (num_chars > 0) {						\
		memcpy(output_buf, output_buf_full + (msg_num *		\
		       MAX_CHARS_PER_MESSAGE), MAX_CHARS_PER_MESSAGE);	\
		if (num_chars > MAX_CHARS_PER_MESSAGE)			\
			output_buf[MAX_CHARS_PER_MESSAGE] = '\0';	\
		else							\
			output_buf[num_chars] = '\0';			\
		print_cmd;						\
		msg_num++;						\
		num_chars -= MAX_CHARS_PER_MESSAGE;			\
	}								\
}									\

#define insecure_printf(fmt, args...)						\
	loop_printf(gapi->write_to_shell(output_buf, MAX_CHARS_PER_MESSAGE),	\
		    fmt, ##args)

#define MSG_LENGTH (1 + TPM_AT_ID_LENGTH + TPM_AT_NONCE_LENGTH)
#define MAX_PACK_SIZE 256

static struct socket *sock;
static struct sock_addr skaddr;
static int type;
struct runtime_api *gapi;

char session_word[32];

int has_network = 0;
int has_bluetooth = 0;
int has_storage = 0;
int has_context_update = 0;
int context_found = 0;

uint8_t bt_am_addrs[2];

static int _str2ip(char *str, unsigned int *ip)
{
	unsigned int a, b, c, d;
	if (sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
		return -1;
	if (a > 255 || b > 255 || c > 255 || d > 255)
		return -1;
	*ip = a | (b << 8) | (c << 16) | (d << 24);
	return 0;
}

static int _parse_ip_port(char *str, unsigned int *addr, unsigned short *nport)
{
	char *port;
	if ((port = strchr(str, ':')) != NULL) {
		*nport = _htons(atoi(&port[1]));
		*port = '\0';
	}
	if (_str2ip(str, addr) < 0)
		return -1;
	if (port)
		*port = ':';
	return 0;
}

int exiting = 0;

static void terminate_network_session(void)
{
	struct socket *tmp;
	if (sock) {
		tmp = sock;
		sock = NULL;
		gapi->close_socket(tmp);
	}
}

static void terminate_bluetooth_session(uint8_t bt_am_addr)
{
	uint8_t msg[BTPACKET_FIXED_DATA_SIZE];
	int ret;

	memset(msg, 0x0, BTPACKET_FIXED_DATA_SIZE);
	ret = gapi->bluetooth_send_data(bt_am_addr, msg,
					BTPACKET_FIXED_DATA_SIZE);
	if (ret)
		goto error;

	ret = gapi->bluetooth_recv_data(bt_am_addr, msg,
					BTPACKET_FIXED_DATA_SIZE);

	if (ret || (msg[0] != 1))
		goto error;

	return;

error:
	insecure_printf("Error: couldn't deauthenticate bluetooth device.\n");
}

static void *yield_resources(void *data)
{
	printf("%s [1]: has_storage = %d, has_context_update = %d, "
	       "context_found = %d, trustworthy_storage_service = %d\n", __func__,
	       has_storage, has_context_update, context_found,
	       trustworthy_storage_service);
	/*
	 * Before writing to storage, we check if it is trustworthy.
	 * Note that this is only needed/useful when we did not find any context
	 * in storage and contacted the server. In future runs, we are simply
	 * trusting this check in the first run.
	 */
	if (has_storage && has_context_update &&
	    (context_found || (!context_found && trustworthy_storage_service))) {
		printf("%s [2]\n", __func__);
		/* write_context_to_storage won't yield if there's an error.
		 * Therefore, we explicitly yield instead of doing it through
		 * write_context_to_storage.
		 */
		context_found = 0;
		trustworthy_storage_service = 0;
		gapi->write_context_to_storage(0);
	}

	if (has_bluetooth) {
		has_bluetooth = 0;
		terminate_bluetooth_session(bt_am_addrs[0]);
		terminate_bluetooth_session(bt_am_addrs[1]);
		gapi->yield_secure_bluetooth_access();
	}

	if (has_network) {
		has_network = 0;
		terminate_network_session();
		gapi->yield_network_access();
	}

	if (has_storage) {
		has_storage = 0;
		gapi->yield_secure_storage_access();
	}
		
	gapi->terminate_app();

	return NULL;
}

/*
 * When there is an update on the limit, this function is called in the main
 * app context. When the update is on the timeout, it is called in the interrupt
 * context.
 */
static void queue_update_callback(uint8_t queue_id, limit_t limit,
				  timeout_t timeout, uint8_t which_update)
{
	if ((limit < 5 || timeout < 5) && !exiting) {
		exiting = 1;
		
		if (which_update == LIMIT_UPDATE) {
			yield_resources(NULL);	

			gapi->terminate_app();
		} else { /* which_update == TIMEOUT_UPDATE */
			/* We are in the interrupt context, hence we schedule
			 * yield_resources() to be executed in a worker_thread
			 * thread.
			 */
			gapi->schedule_func_execution(yield_resources, NULL);	
		}
	}
}

static int request_network_access(void)
{
	int err = 0;
	/* init arguments */
	memset(&skaddr, 0x0, sizeof(skaddr));
	type = SOCK_STREAM;	/* default TCP stream */
	sock = NULL;
	
	char addr[256] = "10.0.0.2:12347";	
	err = _parse_ip_port(addr, &skaddr.dst_addr,
					&skaddr.dst_port);
	if (err < 0) {
		insecure_printf("address format is error\n");
		return err;
	}

	/* init socket */
	sock = gapi->create_socket(AF_INET, type, 0, &skaddr);
	if (!sock) {
		insecure_printf("%s: Error: _socket\n", __func__);
		return -1;
	}

	if (gapi->request_network_access(200, 100, queue_update_callback, NULL,
					 measured_network_pcr)) {
		insecure_printf("%s: Error: network queue access\n", __func__);
		return -1;
	}

	has_network = 1;

	return 0;
}

static int connect_to_server(void)
{
	if (gapi->connect_socket(sock, &skaddr) < 0) {
		insecure_printf("%s: Error: _connect\n", __func__);
		return -1;
	}

	return 0;
}

static int receive_bluetooth_devices_passwords(void)
{
	if (gapi->read_from_socket(sock, context.glucose_monitor_password, 32) < 0) {
		insecure_printf("Error: couldn't read from socket (passwords:1)\n");
		return -1;
	}

	if (gapi->read_from_socket(sock, context.insulin_pump_password, 32) < 0) {
		insecure_printf("Error: couldn't read from socket (passwords:2)\n");
		return -1;
	}

	return 0;
}

static void send_large_packet(uint8_t* data, size_t size)
{
	int packages = size / MAX_PACK_SIZE + 1;
	for (int pack = 0; pack < packages; pack++) {
		int pack_size = ((pack == packages - 1) ?
			(size - pack * MAX_PACK_SIZE) : MAX_PACK_SIZE);

		if (gapi->write_to_socket(sock, data + pack * MAX_PACK_SIZE,
					  pack_size) < 0) {
			insecure_printf("Error: couldn't write to socket "
					"(large packet)\n");
			return;
		}
	}
}

static int perform_remote_attestation(void)
{
	char buf[MSG_LENGTH];
	char uuid[TPM_AT_ID_LENGTH];
	char nonce[TPM_AT_NONCE_LENGTH];
	uint8_t *signature;
	uint8_t *quote;
	uint8_t *packet;
	uint32_t sig_size, quote_size;
	char success = 0;
	char init_cmd = 1;
	uint8_t runtime_proc_id = gapi->get_runtime_proc_id();
	uint8_t pcr_slots[] = {0, (uint8_t) PROC_PCR_SLOT(runtime_proc_id)};
	uint8_t num_pcr_slots = 2;
	int ret;

	if (gapi->write_to_socket(sock, &init_cmd, 1) < 0) {
		insecure_printf("Error: couldn't write to socket (remote "
				"attestation)\n");
		return -1;
	}

	if (gapi->read_from_socket(sock, &success, 1) < 0) {
		insecure_printf("Error: couldn't read from socket (remote "
				"attestation:1)\n");
		return -1;
	}

	if (gapi->read_from_socket(sock, buf, MSG_LENGTH) < 0) {
		insecure_printf("Error: couldn't read from socket (remote "
				"attestation:2)\n");
		return -1;
	}

	if (buf[0] != '0') {
		insecure_printf("Error: invalid attestation request from "
				"the server\n");
		return -1;
	}

	memcpy(uuid, buf + 1, TPM_AT_ID_LENGTH);
	memcpy(nonce, buf + 1 + TPM_AT_ID_LENGTH, TPM_AT_NONCE_LENGTH);

	if (gapi->request_tpm_attestation_report(pcr_slots, num_pcr_slots, nonce,
						 &signature, &sig_size, &quote,
						 &quote_size)) {
		insecure_printf("Error: request for TPM attestation report "
				"failed\n");
		return -1;
	}

	packet = (uint8_t *) malloc(sig_size + quote_size + 1);
	if (!packet) { 
		insecure_printf("Error: %s: couldn't allocate memory for "
				"packet.\n", __func__);
		return -1;
	}
	
	packet[0] = (uint8_t) sig_size;
	memcpy(packet + 1, signature, sig_size);

	memcpy(packet + 1 + sig_size, quote, quote_size);

	send_large_packet(packet, 1 + sig_size + quote_size);
	
	free(packet);
	free(quote);
	free(signature);

	if (gapi->read_from_socket(sock, &success, 1) < 0) {
		insecure_printf("Error: couldn't read from socket (remote "
				"attestation:3)\n");
		return -1;
	}

	if (success != 1) {
		insecure_printf("Error: attestation report not verified\n");
		return -1;
	}

	/* Receieve I/O service PCRs */
	if (gapi->read_from_socket(sock, context.bluetooth_pcr,
				   TPM_EXTEND_HASH_SIZE) < 0) {
		insecure_printf("Error: couldn't read from socket (remote "
				"attestation:4)\n");
		return -1;
	}

	if (gapi->read_from_socket(sock, storage_pcr,
				   TPM_EXTEND_HASH_SIZE) < 0) {
		insecure_printf("Error: couldn't read from socket (remote "
				"attestation:5)\n");
		return -1;
	}

	/* check the storage PCR val */
	ret = memcmp(measured_storage_pcr, storage_pcr,
		     TPM_EXTEND_HASH_SIZE);
	printf("%s [1]: ret = %d\n", __func__, ret);
	if (ret)
		trustworthy_storage_service = 0;
	else
		trustworthy_storage_service = 1;
	

	if (gapi->read_from_socket(sock, network_pcr,
				   TPM_EXTEND_HASH_SIZE) < 0) {
		insecure_printf("Error: couldn't read from socket (remote "
				"attestation:6)\n");
		return -1;
	}

	/* check the network PCR val */
	ret = memcmp(measured_network_pcr, network_pcr, TPM_EXTEND_HASH_SIZE);
	if (ret) {
		printf("Error: %s: network PCR not verified.\n", __func__);
		success = 0;
	} else {
		success = 1;
	}

	/* This is needed for attestation of the network service.
	 * Right after we receive the PCR, we compare it with what we have
	 * from TPM measurements. If they match, we tell the server so that
	 * it can send us secrets or receive confidential information.
	 * Note that the client and server communication is secured end-to-end,
	 * therefore we can trust our message to be delivered correctly and not
	 * delivered at all. Yet, we don't assume that the communications
	 * between the client are secure against side-channels on the client
	 * device. The attestation of the network service tries to defeat that.
	 */
	if (gapi->write_to_socket(sock, &success, 1) < 0) {
		insecure_printf("Error: couldn't write to socket (remote "
				"attestation:2)\n");
		return -1;
	}

	if (!success)
		return -1;

	return 0;
}

static int establish_secure_channel(void)
{
	/* FIXME: implement and then use the secure channel */
	return 0;
}

static void calculate_dose_update_context(uint16_t glucose_measurement,
					  uint8_t *dose, int context_found)
{
	uint64_t current_time;
	uint16_t glucose_measurement_avg;

	if (context_found) {
		current_time = gapi->get_time();
		if (current_time <= context.last_measurement_time) {
			/* Should not happen, but let's check anyway. */
			insecure_printf("Error: stored data seem incorrect. "
					"Discarding.\n");
			goto context_not_found;
		}

		/* simple, dummy calculations */
		if ((current_time - context.last_measurement_time) > 86400) {
			/* more than one day */
			insecure_printf("Stored data are old. Discarding.\n");
			goto context_not_found;
		}

		glucose_measurement_avg = (glucose_measurement +
					   context.glucose_measurement_avg) / 2;
		printf("%s [1]: glucose_measurement_avg = %d\n", __func__,
		       glucose_measurement_avg);

		if (glucose_measurement_avg > 200)
			*dose = 2;
		else if (glucose_measurement_avg > 100)
			*dose = 1;
		else
			*dose = 0;

		context.glucose_measurement_avg = glucose_measurement_avg;
		context.last_measurement_time = current_time;

		return;
	}

context_not_found:
	*dose = (glucose_measurement > 200) ? 2 : 1;
	context.glucose_measurement_avg = glucose_measurement;
	context.last_measurement_time = gapi->get_time();
}

extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
{
	/*
	 * Step 0: Request all needed I/O services. Request the storage service
	 *	   last in order to allow other services to boot, if needed.
	 * Step 1: Check secure storage for previously-stored passwords and
	 *	   measurements. If found, skip to Step 4.
	 * Step 2: Connect to the server and perform remote attestation of
	 *	   the app itself, bluetooth, and network.
	 *	   Upon successful attestation, establish a secure channel.
	 * Step 3: Receive passwords for both bluetooth devices.
	 * Step 4: Authenticate with bluetooth devices.
	 *	   Upon success, read from glucose_monitor (sensor) and write
	 *	   to insulin_pump (actuator).
	 * Step 5: Keep track of the usage of the queues (limit and timeout).
	 *	   Secure yield access when about to expire. For bluetooth,
	 *	   terminate the sessions with devices. For network, terminate
	 *	   the session with the server. For storage, write the latest
	 *	   version of the context data to storage.
	 */
	int ret;
	uint8_t msg[BTPACKET_FIXED_DATA_SIZE];
	uint16_t glucose_measurement;
	uint8_t dose;
	uint32_t num_bt_devices = 2;
	uint8_t bt_device_names[BD_ADDR_LEN * 2];
	printf("%s [1]\n", __func__);

	if (BTPACKET_FIXED_DATA_SIZE != 32) {
		printf("Error: %s: BTPACKET_FIXED_DATA_SIZE must be 32 (%d)\n",
		       __func__, BTPACKET_FIXED_DATA_SIZE);
		return;
	}

	gapi = api;

	/* Step 0 */
	/* Request access to the network service */
	ret = request_network_access();
	if (ret) {
		insecure_printf("%s: Error: network queue access\n", __func__);
		goto terminate;
	}

	/* Request access to the bluetooth service */
	insecure_printf("Connecting to the bluetooth services now.\n");

	/* FIXME: can't check the PCR until new TPM architecture is ready since
	 * after a reboot of the bluetooth proc, its PCR won't match the
	 * expected value.
	 */
	/* This means that glucose_monitor will be index 0 in am_addrs and
	 * insulin_pump will be index 1 */
	memcpy(bt_device_names, glucose_monitor, BD_ADDR_LEN);	
	memcpy(bt_device_names + BD_ADDR_LEN, insulin_pump, BD_ADDR_LEN);	
	
	/* FIXME: can't check the PCR until new TPM architecture is ready since
	 * after a reboot of the bluetooth proc, its PCR won't match the
	 * expected value.
	 */
	ret = gapi->request_secure_bluetooth_access(bt_device_names,
						    num_bt_devices, 200, 100,
						    bt_am_addrs,
						    queue_update_callback,
						    //context.bluetooth_pcr);
						    NULL);
	if (ret) {
		insecure_printf("Error: couldn't get access to bluetooth.\n");
		goto terminate;
	}

	has_bluetooth = 1;
	insecure_printf("Connected to the bluetooth service to use the glucose "
			"monitor and insulin pump.\n");



	/* Step 1 (including part of Step 0 to request access to storage) */
	uint8_t secure_storage_key[STORAGE_KEY_SIZE];
	/* generate a key */
	for (int i = 0; i < STORAGE_KEY_SIZE; i++)
		secure_storage_key[i] = i + 5;

	/* FIXME: how to do local attestation for storage, i.e., check its PCR
	 * val?
	 */

	api->set_up_secure_storage_key(secure_storage_key);
	ret = api->set_up_context((void *) &context, sizeof(struct app_context),
				  0, 100, 200, 100, queue_update_callback, NULL,
				  measured_storage_pcr);
	printf("%s [1.1]: ret = %d\n", __func__, ret);
	if (!ret) {
		has_storage = 1;
		if (!memcmp(context.signature, expected_context_signature,
			    CONTEXT_SIGNATURE_SIZE)) {
			insecure_printf("Found measurements from previous "
					"run(s).\n");
			context_found = 1;
			goto new_measurement;
		}
	}
		
	memcpy(context.signature, expected_context_signature,
	       CONTEXT_SIGNATURE_SIZE);
	
	/* Step 2 */
	ret = connect_to_server();
	if (ret) {
		insecure_printf("Error: couldn't connect to the server.\n");
		goto terminate;
	}
	printf("%s [2]\n", __func__);

	ret = perform_remote_attestation();
	if (ret) {
		insecure_printf("Error: remote attestation failed.\n");
		goto terminate;
	}
	printf("%s [3]\n", __func__);

	/* From here on, we need to check the PCR for I/O services we get access
	 * to.
	 */

	ret = establish_secure_channel();
	if (ret) {
		insecure_printf("Error: couldn't establish a secure channel.\n");
		goto terminate;
	}
	printf("%s [4]\n", __func__);

	/* Step 3 */
	ret = receive_bluetooth_devices_passwords();
	if (ret) {
		insecure_printf("Error: couldn't receive the passwords for"
				"bluetooth devices.\n");
		goto terminate;
	}

new_measurement:
	/* Step 4: authenticate & send/receive messages */
	/* Step 4.1: get a measurement from the glucose monitor */
	//insecure_printf("Connecting to the bluetooth services now.\n");

	///* FIXME: can't check the PCR until new TPM architecture is ready since
	// * after a reboot of the bluetooth proc, its PCR won't match the
	// * expected value.
	// */
	///* This means that glucose_monitor will be index 0 in am_addrs and
	// * insulin_pump will be index 1 */
	//memcpy(bt_device_names, glucose_monitor, BD_ADDR_LEN);	
	//memcpy(bt_device_names + BD_ADDR_LEN, insulin_pump, BD_ADDR_LEN);	
	//
	///* FIXME: can't check the PCR until new TPM architecture is ready since
	// * after a reboot of the bluetooth proc, its PCR won't match the
	// * expected value.
	// */
	//ret = gapi->request_secure_bluetooth_access(bt_device_names,
	//					    num_bt_devices, 200, 100,
	//					    bt_am_addrs,
	//					    queue_update_callback,
	//					    //context.bluetooth_pcr);
	//					    NULL);
	//if (ret) {
	//	insecure_printf("Error: couldn't get access to bluetooth.\n");
	//	goto terminate_network;
	//}

	//has_bluetooth = 1;
	//insecure_printf("Connected to the bluetooth service to use the glucose "
	//		"monitor and insulin pump.\n");

	/* Authenticate */
	ret = gapi->bluetooth_send_data(bt_am_addrs[0],
					context.glucose_monitor_password,
					BTPACKET_FIXED_DATA_SIZE);
	if (ret) {
		insecure_printf("Error: couldn't successfully send a message "
				"to the glucose monitor for authentication.\n");
		goto terminate;
	}

	ret = gapi->bluetooth_recv_data(bt_am_addrs[0], msg,
					BTPACKET_FIXED_DATA_SIZE);
	if (ret || (msg[0] != 1)) {
		insecure_printf("Error: couldn't authenticate with the glucose "
				"monitor\n");
		goto terminate;
	}

	insecure_printf("Authenticated with the glucose monitor.\n");

	/* send/receive msgs */
	memset(msg, 0x0, BTPACKET_FIXED_DATA_SIZE);
	msg[0] = 1;
	ret = gapi->bluetooth_send_data(bt_am_addrs[0], msg,
					BTPACKET_FIXED_DATA_SIZE);
	if (ret) {
		insecure_printf("Error: couldn't successfully send a message "
				"to the glucose monitor.\n");
		goto terminate;
	}

	ret = gapi->bluetooth_recv_data(bt_am_addrs[0], msg,
					BTPACKET_FIXED_DATA_SIZE);
	if (ret || (msg[0] != 1)) {
		insecure_printf("Error: couldn't get measurement from the "
				"glucose monitor.\n");
		goto terminate;
	}

	glucose_measurement = *((uint16_t *) &msg[1]);
	insecure_printf("glucose measurement = %d (mg/dL).\n",
			glucose_measurement);

	/* Step 4.2: if needed, send an injection request to the insulin pump */
	calculate_dose_update_context(glucose_measurement, &dose, context_found);
	if (!dose) {
		insecure_printf("No insulin injection is needed. Terminating.\n");
		goto terminate;
	}
	printf("%s [5]\n", __func__);

	has_context_update = 1;

	//terminate_bluetooth_session();
	//has_bluetooth = 0;
	//gapi->yield_secure_bluetooth_access();
	printf("%s [6]\n", __func__);

	insecure_printf("Need to inject %d doses of insulin.\n", dose);

	///* FIXME: can't check the PCR until new TPM architecture is ready since
	// * after a reboot of the bluetooth proc, its PCR won't match the
	// * expected value.
	// */
	//ret = gapi->request_secure_bluetooth_access(insulin_pump, 200, 100,
	//					    queue_update_callback,
	//					    //context.bluetooth_pcr);
	//					    NULL);
	//printf("%s [7]\n", __func__);
	//if (ret) {
	//	insecure_printf("Error: couldn't get access to bluetooth.\n");
	//	goto terminate;
	//}

	//has_bluetooth = 1;
	//insecure_printf("Connected to the insulin pump.\n");

	/* Authenticate */
	ret = gapi->bluetooth_send_data(bt_am_addrs[1],
					context.insulin_pump_password,
					BTPACKET_FIXED_DATA_SIZE);
	if (ret) {
		insecure_printf("Error: couldn't successfully send a message "
				"to the insulin pump for authentication.\n");
		goto terminate;
	}

	printf("%s [8]\n", __func__);
	ret = gapi->bluetooth_recv_data(bt_am_addrs[1], msg,
				  BTPACKET_FIXED_DATA_SIZE);
	if (ret || (msg[0] != 1)) {
		insecure_printf("Error: couldn't authenticate with the insulin "
				"pump\n");
		goto terminate;
	}

	insecure_printf("Authenticated with the insulin pump.\n");

	/* send/receive msgs */
	memset(msg, 0x0, BTPACKET_FIXED_DATA_SIZE);
	msg[0] = 1;
	msg[1] = dose;
	ret = gapi->bluetooth_send_data(bt_am_addrs[1], msg,
					BTPACKET_FIXED_DATA_SIZE);
	if (ret) {
		insecure_printf("Error: couldn't successfully send a message "
				"to the insulin pump.\n");
		goto terminate;
	}

	ret = gapi->bluetooth_recv_data(bt_am_addrs[1], msg,
					BTPACKET_FIXED_DATA_SIZE);
	if (ret || (msg[0] != 1)) {
		insecure_printf("Error: insulin injection failed.\n");
		goto terminate;
	}

	insecure_printf("Insulin successfully adminstered.\n");

	/* Step 5 */
terminate:
	/*
	 * Before writing to storage, we check if it is trustworthy.
	 * Note that this is only needed/useful when we did not find any context
	 * in storage and contacted the server. In future runs, we are simply
	 * trusting this check in the first run.
	 */
	printf("%s [5]: context_found = %d\n", __func__, context_found);
	printf("%s [6]: trustworthy_storage_service = %d\n", __func__,
	       trustworthy_storage_service);
	if (context_found || (!context_found && trustworthy_storage_service)) {
		insecure_printf("Storing data to storage for future.\n");
		/* write_context_to_storage won't yield if there's an error.
		 * Therefore, we explicitly yield instead of doing it through
		 * write_context_to_storage.
		 */
		context_found = 0;
		trustworthy_storage_service = 0;
		gapi->write_context_to_storage(0);
	}

	if (has_storage) {
		has_storage = 0;
		gapi->yield_secure_storage_access();
	}

	if (has_bluetooth) {
		has_bluetooth = 0;
		terminate_bluetooth_session(bt_am_addrs[0]);
		terminate_bluetooth_session(bt_am_addrs[1]);
		gapi->yield_secure_bluetooth_access();
	}

	if (has_network) {
		has_network = 0;
		terminate_network_session();
		gapi->yield_network_access();
	}
}

#endif
