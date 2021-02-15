#ifndef ARCH_SEC_HW

/* bank_client app
 *
 * Based on:
 * socket_client.c
 * attest_client.c
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

uint8_t keyboard_pcr[TPM_EXTEND_HASH_SIZE];
uint8_t serial_out_pcr[TPM_EXTEND_HASH_SIZE];
uint8_t network_pcr[TPM_EXTEND_HASH_SIZE];
uint8_t measured_network_pcr[TPM_EXTEND_HASH_SIZE];

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

#define secure_printf(fmt, args...)						\
	loop_printf(gapi->write_to_secure_serial_out(output_buf), fmt, ##args)

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
int has_keyboard = 0;
int has_secure_serial_out = 0;
int has_session_word = 0;

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

/* Can be called with secure keyboard/serial_out or not.
 * Don't write to the terminal.
 */
static void terminate_network_session(void)
{
	struct socket *tmp;
	if (sock) {
		tmp = sock;
		sock = NULL;
		gapi->close_socket(tmp);
	}
}



static void *yield_resources(void *data)
{
	if (has_secure_serial_out)
		gapi->yield_secure_serial_out();

	if (has_keyboard)
		gapi->yield_secure_keyboard();

	if (has_network) {
		terminate_network_session();
		gapi->yield_network_access();
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
		if (has_secure_serial_out && has_session_word) {
			secure_printf("%s: Session is terminating. Stop using "
				      "the app now as it is no longer secure. "
				      "If needed, you can restart the app.\n",
				      session_word);
		} else if (has_secure_serial_out && !has_session_word) {
			secure_printf("App is terminating. Stop using "
				      "the app now as it is no longer secure. "
				      "If needed, you can restart the app.\n");
		} else { /* !has_secure_serial_out */
			insecure_printf("App is terminating.\n");
		}

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

static int connect_to_server(void)
{
	int err = 0;
	/* init arguments */
	memset(&skaddr, 0x0, sizeof(skaddr));
	type = SOCK_STREAM;	/* default TCP stream */
	sock = NULL;
	
	char addr[256] = "10.0.0.2:12346";	
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

	if (gapi->connect_socket(sock, &skaddr) < 0) {
		insecure_printf("%s: Error: _connect\n", __func__);
		return -1;
	}

	return 0;
}

static int get_user_secret(char *username, char *secret)
{
	char success = 0;

	if (gapi->write_to_socket(sock, username, 32) < 0) {
		insecure_printf("Error: couldn't write to socket (username)\n");
		return -1;
	}

	if (gapi->read_from_socket(sock, &success, 1) < 0) {
		insecure_printf("Error: couldn't read from socket (username:1)\n");
		return -1;
	}

	if (success != 1) {
		insecure_printf("Error: invalid username\n");
		return -1;
	}
	
	if (gapi->read_from_socket(sock, secret, 32) < 0) {
		insecure_printf("Error: couldn't read from socket (username:2)\n");
		return -1;
	}

	return 0;
}

/*
 * This function is called while holding the secure keyboard/serial_out.
 * Therefore, we can't use insecure_printf.
 */
static int send_password_to_server(char *password)
{
	char success = 0;

	if (gapi->write_to_socket(sock, password, 32) < 0) {
		secure_printf("Error: couldn't write to socket (password)\n");
		return -1;
	}

	if (gapi->read_from_socket(sock, &success, 1) < 0) {
		secure_printf("Error: couldn't read from socket (password)\n");
		return -1;
	}

	if (success != 1) {
		secure_printf("Error: invalid password\n");
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
	if (gapi->read_from_socket(sock, keyboard_pcr, TPM_EXTEND_HASH_SIZE) < 0) {
		insecure_printf("Error: couldn't read from socket (remote "
				"attestation:4)\n");
		return -1;
	}

	if (gapi->read_from_socket(sock, serial_out_pcr, TPM_EXTEND_HASH_SIZE) < 0) {
		insecure_printf("Error: couldn't read from socket (remote "
				"attestation:5)\n");
		return -1;
	}

	if (gapi->read_from_socket(sock, network_pcr, TPM_EXTEND_HASH_SIZE) < 0) {
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

/* Called with secure keyboard/serial_out */
static int log_in(void)
{
	char username[32], secret[32], password[32], c;
	int size, ret, i;
	uint32_t rand;

	memset(username, 0x0, 32);
	memset(secret, 0x0, 32);
	memset(password, 0x0, 32);
	memset(session_word, 0x0, 32);
	/*
	 * Ask for user's username.
	 * Note that this step does not need to be secure since we haven't
	 * established any form of trust with the user yet.
	 * Note: one might wonder if malware can pretend to be the bank_client
	 * app, get the username, and then use that to retrieve the user's
	 * secret, allowing it to further fool the user. This is not effective
	 * as the server won't release the secret to an app that doesn't
	 * successfully pass the remote attestation.
	 */
	secure_printf("This is the bank_client speaking.\n");
	secure_printf("Provide your username to log in (but NOT your password "
		      "yet):\n");

	size = 0;
	/* FIXME: handle backspace in the username */
	for (i = 0; i < 24; i++) {
		gapi->read_char_from_secure_keyboard(&c);
#ifdef ARCH_SEC_HW
		if (c == '\r') {
#else
		if (c == '\n') {
#endif
			break;
		}
		
		username[i] = c;
		size++;
	}

	if (size > 16) {
		secure_printf("Username can't have more than 16 characters.\n");
		return -1;
	}

	/*
	 * Get the user's secret from the server.
	 */
	ret = get_user_secret(username, secret);
	if (ret) {
		secure_printf("Error: could not get user's secret from the "
			      "server.\n");
		return -1;
	}

	/*
	 * Show the secret to the user and ask for the password, all securely.
	 */
	secure_printf("Here's your secret registered with the bank: %s\n", secret);
	secure_printf("If this is NOT correct, do NOT proceed.\n\n");

	secure_printf("Next, we will collect your password, but pay attention "
		      "to these instructions.\n");
	secure_printf("We will collect your password through a secure "
		      "session.\n");
	secure_printf("When the session is about to expire, we will send you "
		      "a warning.\n");
	secure_printf("Do not enter any part of your password after the "
		      "warning.\n\n");

	secure_printf("Enter your password now (no more than 16 characters):\n");

	size = 0;
	/* FIXME: handle backspace in the password */
	for (i = 0; i < 24; i++) {
		gapi->read_char_from_secure_keyboard(&c);
#ifdef ARCH_SEC_HW
		if (c == '\r') {
#else
		if (c == '\n') {
#endif
			break;
		}
		
		password[i] = c;
		size++;
	}

	if (size > 16) {
		secure_printf("Password can't have more than 16 characters.\n");
		return -1;
	}

	ret = send_password_to_server(password);
	if (ret) {
		secure_printf("Error: incorrect password.\n");
		return -1;
	}

	secure_printf("You have successfully logged in.\n\n");

	rand = gapi->get_random_uint();
	sprintf(session_word, "SESSION%u", rand);

	secure_printf("Your session keyword is %s.\n", session_word);
	has_session_word = 1;
	secure_printf("%s: Look for the session keyword at the beginning of "
		      "each line.\n", session_word);
	secure_printf("%s: If not correct or available, stop using the app "
		      "immediately.\n", session_word);

	return 0;
}

/* Called with secure keyboard/serial_out.
 * Also, must print with session_word.
 */
static int show_account_info(void)
{
	char cmd, success;
	uint32_t balance;

	cmd = 1; /* retrive account balance */
	if (gapi->write_to_socket(sock, &cmd, 1) < 0) {
		secure_printf("%s: Error: couldn't write to socket (balance)\n",
			      session_word);
		return -1;
	}

	if (gapi->read_from_socket(sock, &success, 1) < 0) {
		secure_printf("%s: Error: couldn't read from socket "
			      "(balance:1)\n", session_word);
		return -1;
	}

	if (success != 1) {
		secure_printf("%s: Error: couldn't retrieve balance\n",
			      session_word);
		return -1;
	}

	if (gapi->read_from_socket(sock, &balance, 4) < 0) {
		secure_printf("%s: Error: couldn't read from socket "
			      "(balance:2)\n", session_word);
		return -1;
	}

	/*
	 * Show the account balance securely.
	 */
	secure_printf("%s: your balance is $%d\n", session_word, balance);

	return 0;
}

extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
{
	/*
	 * Step 1: Connect to the server and perform remote attestation of
	 *	   the app itself, keyboard, serial_out, and network.
	 *	   Upon successful attestation, establish a secure channel.
	 * Step 2: Ask for user's username.
	 *	   Send the username to the server and retrieve user's login
	 *	   secret, through secure UI.
	 *	   Send the hash of the password to the server to complete login.
	 * Step 3: Retrieve user's account information and show securely to the
	 *	   user.
	 * Step 4: Keep track of the usage of the queues (limit and timeout).
	 *	   Secure yield access when about to expire. For secure UI,
	 *	   show a session expiration message to the user. For network,
	 *	   terminate the session with the server.
	 */
	int ret;

	gapi = api;

	/* Step 1 */
	ret = connect_to_server();
	if (ret) {
		insecure_printf("Error: couldn't connect to the server.\n");
		return;
	}

	ret = perform_remote_attestation();
	if (ret) {
		insecure_printf("Error: remote attestation failed.\n");
		goto terminate_network;
	}

	/* From here on, we need to check the PCR for I/O services we get access
	 * to.
	 */

	ret = establish_secure_channel();
	if (ret) {
		insecure_printf("Error: couldn't establish a secure channel.\n");
		goto terminate_network;
	}

	/* Request secure keyboard/serial_out and use secure_printf from now on. */
	ret = gapi->request_secure_keyboard(100, 100, queue_update_callback,
					    keyboard_pcr);
	if (ret) {
		insecure_printf("Error: could not get secure access to "
				"keyboard\n");
		goto terminate_network;
	}

	has_keyboard = 1;

	ret = gapi->request_secure_serial_out(1000, 100, queue_update_callback,
					      serial_out_pcr);
	if (ret) {
		gapi->yield_secure_keyboard();
		insecure_printf("Error: could not get secure access to "
				"serial_out (log_in)\n");
		goto terminate_keyboard;
	}

	has_secure_serial_out = 1;

	/* From here on, our prints should use secure_printf. */

	/* Step 2 */
	ret = log_in();
	if (ret) {
		secure_printf("Error: couldn't log in to the server.\n");
		goto terminate;
	}

	/* From here on, our prints should start with the session_word. */

	/* Step 3 */
	ret = show_account_info();
	if (ret) {
		secure_printf("%s: Error: couldn't successfully show account "
			      "info.\n", session_word);
		goto terminate;
	}

	/* Step 4 */
terminate:
	/*
	 * No more interacting with the user after this.
	 */
	has_secure_serial_out = 0;
	gapi->yield_secure_serial_out();

terminate_keyboard:
	has_keyboard = 0;
	gapi->yield_secure_keyboard();

terminate_network:
	has_network = 0;
	terminate_network_session();
	gapi->yield_network_access();
}

#endif
