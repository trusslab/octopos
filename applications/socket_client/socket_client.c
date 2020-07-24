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

/* FIXME: how does the app know the size of the buf? */
char output_buf[64];
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

static void send_receive(struct runtime_api *api)
{
	char buf[32];
	int len;
	printf("%s [1]\n", __func__);

	if (api->connect_socket(sock, &skaddr) < 0) {
		printf("%s: Error: _connect\n", __func__);
		return;
	}
	printf("%s [2]\n", __func__);

	insecure_printf("Type your message: ");
	int ret = api->read_from_shell(buf, &len);
	if (ret) {
		printf("%s: Error: read stdin\n", __func__);
		return;
	}
	printf("%s [3]\n", __func__);
	if (api->write_to_socket(sock, buf, len) < 0) {
		printf("%s: Error: _write\n", __func__);
		return;
	}
	printf("%s [4]\n", __func__);
	while ((len = api->read_from_socket(sock, buf, 512)) > 0) {
		insecure_printf("%.*s\n", len, buf);
	}
	printf("%s [5]\n", __func__);
}

extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
{
	int err = 0;
	/* init arguments */
	memset(&skaddr, 0x0, sizeof(skaddr));
	type = SOCK_STREAM;	/* default TCP stream */
	sock = NULL;
	printf("%s [1]\n", __func__);
	
	char addr[256] = "10.0.0.2:12345";	
	err = _parse_ip_port(addr, &skaddr.dst_addr,
					&skaddr.dst_port);
	if (err < 0) {
		printf("address format is error\n");
		return;
	}
	printf("%s [2]\n", __func__);

	/* init socket */
	sock = api->create_socket(AF_INET, type, 0, &skaddr);
	if (!sock) {
		printf("%s: Error: _socket\n", __func__);
		goto out;
	}
	printf("%s [3]\n", __func__);

	if (api->request_network_access(200)) {
		printf("%s: Error: network queue access\n", __func__);
		return;
	}
	printf("%s [4]\n", __func__);

	send_receive(api);
	printf("%s [5]\n", __func__);

out:	/* close and out */
	struct socket *tmp;
	if (sock) {
		tmp = sock;
		sock = NULL;
		api->close_socket(tmp);
	}
	api->yield_network_access();
	printf("%s [6]\n", __func__);
}
#endif
