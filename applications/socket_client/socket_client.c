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


char througput_test_buf [256] = "Claudius, King of Denmark. Marcellus, Officer. Hamlet, son to the former, and nephew to the present king. Polonius, Lord Chamberlain.Horatio, friend to Hamlet.  Laertes, son to Polonius. Voltemand, courtier. Cornelius, courtier. Rosencrantz, courtier.Guil";
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
#ifdef ARCH_SEC_HW
static void delay_print(int num)
{
	for (int i=0 ; i<num; i++)
		printf("!");
	printf("\r\n");
}
#endif
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
	if (api->connect_socket(sock, &skaddr) < 0) {
#ifdef ARCH_SEC_HW
		print("send_receive [0.5]\n\r");
#endif /* ARCH_SEC_HW */
		printf("%s: Error: _connect\n", __func__);
		return;
	}
	insecure_printf("Type your message: ");
	int ret = api->read_from_shell(buf, &len);
	if (ret) {
		printf("%s: Error: read stdin\n", __func__);
		return;
	}
	if (api->write_to_socket(sock, buf, len) < 0) {
		printf("%s: Error: _write\n", __func__);
		return;
	}
#ifdef ARCH_SEC_HW
	delay_print(200);
#endif
	while ((len = api->read_from_socket(sock, buf, 512)) > 0) {
		insecure_printf("%.*s\n", len, buf);
	}
	printf("read done\n\r");
}

#ifdef ARCH_SEC_HW
static void latency_test(struct runtime_api *api)
{
	char buf[32] = "1";
	char buf2[32] = "2";
	int len;
	len = strlen(buf);
	if (api->connect_socket(sock, &skaddr) < 0) {
		printf("%s: Error: _connect\n", __func__);
		return;
	}
	if (api->write_to_socket(sock, buf, len) < 0) {
		printf("%s: Error: _write\n", __func__);
		return;
	}
	delay_print(20);
	len = api->read_from_socket(sock, buf, 512);
	len = strlen(buf2);
	if (api->write_to_socket(sock, buf2, len) < 0) {
		printf("%s: Error: _write\n", __func__);
		return;
	}
}
static void throughput_test(struct runtime_api *api)
{
	char buf[32] = "1";
	int len;
	len = strlen(buf);
	if (api->connect_socket(sock, &skaddr) < 0) {
		print("send_receive [0.5]\n\r");
		printf("%s: Error: _connect\n", __func__);
		return;
	}
	if (api->write_to_socket(sock, buf, len) < 0) {
		printf("%s: Error: _write\n", __func__);
		return;
	}
	delay_print(20);
	len = api->read_from_socket(sock, buf, 512);
	printf("... %.*s\n\r",len,buf);
	len = strlen(througput_test_buf);
	for (int i=0; i<2; i++){
		printf("%d\n\r",i);
		througput_test_buf[0] = i;
		if (api->write_to_socket(sock, througput_test_buf, 256) < 0) {
			printf("%s: Error: _write\n", __func__);
			return;
		}
	}
}
#endif /* ARCH_SEC_HW */


#ifndef ARCH_SEC_HW
extern "C" __attribute__ ((visibility ("default")))
void app_main(struct runtime_api *api)
#else /*ARCH_SEC_HW*/
void socket_client(struct runtime_api *api)
#endif /*ARCH_SEC_HW*/
{
	int err = 0;
	struct socket *tmp;
	/* init arguments */
	memset(&skaddr, 0x0, sizeof(skaddr));
	type = SOCK_STREAM;	/* default TCP stream */
	sock = NULL;
#ifndef ARCH_SEC_HW
	char addr[256] = "10.0.0.2:12345";
#else
	char addr[256] = "192.168.0.1:12345";
#endif
	err = _parse_ip_port(addr, &skaddr.dst_addr,
					&skaddr.dst_port);
	if (err < 0) {
		printf("address format is error\n");
		return;
	}
	printf("%s: 0x%x , %u \n\r",__func__, skaddr.dst_addr, skaddr.dst_port);
	/* init socket */
	sock = api->create_socket(AF_INET, type, 0, &skaddr);
	if (!sock) {
		printf("%s: Error: _socket\n", __func__);
		goto out;
	}

	if (api->request_network_access(4095, 100, NULL, NULL, NULL)) {
		printf("%s: Error: network queue access\n", __func__);
		return;
	}
#ifdef ARCH_SEC_HW
	delay_print(20);
#endif
	api->bind_socket(sock, &skaddr);
#ifdef ARCH_SEC_HW
	delay_print(500);
#endif
	send_receive(api);
//	latency_test(api);
//	throughput_test(api);


out:	/* close and out */
	if (sock) {
		tmp = sock;
		sock = NULL;
		api->close_socket(tmp);
	}
	api->yield_network_access();
}
