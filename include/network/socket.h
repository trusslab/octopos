#ifndef __SOCKET_H
#define __SOCKET_H

#include "wait.h"

enum socket_state {
	SS_UNCONNECTED = 1,
	SS_BIND,
	SS_LISTEN,
	SS_CONNECTING,
	SS_CONNECTED,
	SS_MAX
};

enum sock_type {
	SOCK_STREAM = 1,
	SOCK_DGRAM,
	SOCK_RAW,
	SOCK_MAX
};

enum socket_family {
	AF_INET = 1
};

struct socket;
struct sock_addr;
/* protocol dependent socket apis */
struct socket_ops {
	int (*socket)(struct socket *, int);
	int (*close)(struct socket *);
	int (*accept)(struct socket *, struct socket *, struct sock_addr *);
	int (*listen)(struct socket *, int);
	int (*bind)(struct socket *, struct sock_addr *);
	int (*connect)(struct socket *, struct sock_addr *);
	int (*read)(struct socket *, void *, int);
	int (*write)(struct socket *, void *, int);
	int (*send)(struct socket *, void *, int, struct sock_addr *);
	struct pkbuf *(*recv)(struct socket *);
};

struct socket {
	unsigned int state;
	unsigned int family;	/* socket family: always AF_INET */
	unsigned int type;	/* l4 protocol type: stream, dgram, raw */
	struct tapip_wait sleep;
	struct socket_ops *ops;
	struct sock *sk;
	int refcnt;		/* refer to linux file::f_count */
};

extern struct socket *_socket(int, int, int);
extern int _listen(struct socket *, int);
extern void _close(struct socket *);
extern int _bind(struct socket *, struct sock_addr *);
extern struct socket *_accept(struct socket *, struct sock_addr *);
extern int _send(struct socket *, void *, int, struct sock_addr *);
extern int _connect(struct socket *, struct sock_addr *);
extern int _read(struct socket *, void *, int);
extern int _write(struct socket *, void *, int);
extern struct pkbuf *_recv(struct socket *);
extern void socket_init(void);

#endif	/* socket.h */
