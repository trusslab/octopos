#ifndef ARCH_SEC_HW

/* socket_client app */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>
#include <octopos/runtime.h>
#include <octopos/storage.h>
#include <network/sock.h>
#include <network/socket.h>

#define ID_LENGTH 16
#define NONCE_LENGTH 16
#define MSG_LENGTH (1 + ID_LENGTH + 2 + NONCE_LENGTH)
#define MAX_PACK_SIZE 256

/* FIXME: how does the app know the size of the buf? */
char output_buf[256];
int num_chars = 0;
#define secure_printf(fmt, args...) {memset(output_buf, 0x0, 64); sprintf(output_buf, fmt, ##args);	\
				     api->write_to_secure_serial_out(output_buf);}			\

#define insecure_printf(fmt, args...) {memset(output_buf, 0x0, 64); num_chars = sprintf(output_buf, fmt, ##args);\
				     api->write_to_shell(output_buf, num_chars);}				 \

static struct socket *sock;
static struct sock_addr skaddr;
static int type;

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

void send_large_packet(struct runtime_api *api, uint8_t* data, size_t size)
{
	int packages = size / MAX_PACK_SIZE + 1;
	for (int pack = 0; pack < packages; pack++) {
		int pack_size = ((pack == packages - 1) ?
			(size - pack * MAX_PACK_SIZE) : MAX_PACK_SIZE);

		if (api->write_to_socket(sock, data + pack * MAX_PACK_SIZE, pack_size) < 0) {
			printf("%s: Error: _write\n", __func__);
			return;
		}
	}
}

static void send_receive(struct runtime_api *api)
{
	char buf[MSG_LENGTH];
	int len;

	if (api->connect_socket(sock, &skaddr) < 0) {
		printf("%s: Error: _connect\n", __func__);
		return;
	}

	if ((len = api->read_from_socket(sock, buf, 512)) > 0) {
		// char preserve = buf[0];
		char uuid[ID_LENGTH];
		char slot[3] = { 0 };
		char nonce[NONCE_LENGTH];
		
		memcpy(uuid, buf + 1, ID_LENGTH);
		memcpy(slot, buf + 1 + ID_LENGTH, 2);
		memcpy(nonce, buf + 1 + ID_LENGTH + 2, NONCE_LENGTH);

		int pcr_slot = atoi(slot);
		api->tpm_remote_attest_requst(pcr_slot, nonce, NONCE_LENGTH);

		uint8_t sig_buf[256];
		api->recv_msg_on_tpm(sig_buf);
		// int op = sig_buf[0];
		int sig_size = sig_buf[1];

		uint8_t quote[4096];
		quote[0] = sig_size;
		memcpy(quote + 1, &sig_buf[2], sig_size);

		FILE* quote_file = fopen("quote_info", "r");
		fseek(quote_file, 0L, SEEK_END);
		int quote_size = ftell(quote_file);
		rewind(quote_file);
		char* quote_info = (char *)malloc(quote_size);
		fread(quote_info, quote_size, 1, quote_file);
		fclose(quote_file);
		memcpy(quote + 1 + sig_size, quote_info, quote_size);

		send_large_packet(api, quote, 1 + sig_size + quote_size);
		
		free(quote_info);
	}
}

extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
{
	int err = 0;
	/* init arguments */
	memset(&skaddr, 0x0, sizeof(skaddr));
	type = SOCK_STREAM;	/* default TCP stream */
	sock = NULL;
	
	char addr[256] = "10.0.0.2:10001";
	err = _parse_ip_port(addr, &skaddr.dst_addr,
					&skaddr.dst_port);
	if (err < 0) {
		printf("address format is error\n");
		return;
	}

	/* init socket */
	sock = api->create_socket(AF_INET, type, 0, &skaddr);
	if (!sock) {
		printf("%s: Error: _socket\n", __func__);
		goto out;
	}

	if (api->request_network_access(200)) {
		printf("%s: Error: network queue access\n", __func__);
		return;
	}

	send_receive(api);

out:	/* close and out */
	struct socket *tmp;
	if (sock) {
		tmp = sock;
		sock = NULL;
		api->close_socket(tmp);
	}
	api->yield_network_access();
}
#endif
