/*
 * TCP state machine based on RFC 793 #SEGMENT ARRIVE
 */
#include "lib.h"
#include "netif.h"
#include "tcp.h"
#include "ip.h"

const char *tcp_state_string[TCP_MAX_STATE] = {
	"Unknown tcp state: 0",
	"CLOSED",
	"LISTEN",
	"SYN-RECV",
	"SYN-SENT",
	"ESTABLISHED",
	"CLOSE-WAIT",
	"LAST-ACK",
	"FIN-WAIT-1",
	"FIN-WAIT-2",
	"CLOSING",
	"TIME-WAIT",
};

static _inline void tcp_dbg_state(struct tcp_sock *tsk)
{
	/* state debug information */
	if (!tsk)
		tcpsdbg("CLOSED");
	else if (tsk->state < TCP_MAX_STATE)
		tcpsdbg("%s", tcp_state_string[tsk->state]);
	else
		tcpsdbg("Unknown tcp state: %d", tsk->state);
}

/*
 * FIXME: this is a temp method for allocating SND.ISS
 *        See RFC 793/1122 to implement standard algorithm
 */
unsigned int alloc_new_iss(void)
{
	static unsigned int iss = 12345678;
	if (++iss >= 0xffffffff)
		iss = 12345678;
	return iss;
}

static struct tcp_sock *tcp_listen_child_sock(struct tcp_sock *tsk,
						struct tcp_segment *seg)
{
	struct sock *newsk = tcp_alloc_sock(tsk->sk.protocol);
	struct tcp_sock *newtsk = tcpsk(newsk);
	tcp_set_state(newtsk, TCP_SYN_RECV);
	newsk->sk_saddr = seg->iphdr->ip_dst;
	newsk->sk_daddr = seg->iphdr->ip_src;
	newsk->sk_sport = seg->tcphdr->dst;
	newsk->sk_dport = seg->tcphdr->src;
	/* add to establish hash table for third ACK */
	if (tcp_hash(&newtsk->sk) < 0) {
		free(newsk);
		return NULL;
	}
	/*
	 * Why to get parent reference?
	 * To avoid parent accidental release.
	 * e.g: Parent is interrupted by user
	 *      when child is pending in three-way handshake.
	 */
	newtsk->parent = get_tcp_sock(tsk);
	/* FIXME: add limit to listen queue */
	list_add(&newtsk->list, &tsk->listen_queue);
	/* reference for being listed into parent queue */
	return get_tcp_sock(newtsk);
}

static void tcp_listen(struct pkbuf *pkb, struct tcp_segment *seg,
			struct tcp_sock *tsk)
{
	struct tcp_sock *newtsk;
	struct tcp *tcphdr = seg->tcphdr;
	tcpsdbg("LISTEN");
	/* first check for an RST */
	tcpsdbg("1. check rst");
	if (tcphdr->rst)
		goto discarded;
	/* sencod check for an AKC */
	tcpsdbg("2. check ack");
	if (tcphdr->ack) {
		tcp_send_reset(tsk, seg);
		goto discarded;
	}
	/* third check for a SYN (security check is ignored) */
	tcpsdbg("3. check syn");
	/* RFC 2873: ignore the security/compartment check */
	/*
	 * Should we send a reset for non-syn?
	 * -Yes for xinu.
	 * -No for linux.
	 * +No for tapip.
	 */
	if (!tcphdr->syn)
		goto discarded;
	/* set for first syn */
	newtsk = tcp_listen_child_sock(tsk, seg);
	if (!newtsk) {
		tcpsdbg("cannot alloc new sock");
		goto discarded;
	}
	newtsk->irs = seg->seq;
	newtsk->iss = alloc_new_iss();
	newtsk->rcv_nxt = seg->seq + 1;;
	/* send seq=iss, ack=rcv.nxt, syn|ack */
	tcp_send_synack(newtsk, seg);
	newtsk->snd_nxt = newtsk->iss + 1;
	newtsk->snd_una = newtsk->iss;
	/* fourth other text or control:
	 *  Any other control or text-bearing segment (not containing SYN)
	 *  must have an ACK and thus would be discarded by the ACK
	 *  processing.  An incoming RST segment could not be valid, since
	 *  it could not have been sent in response to anything sent by this
	 *  incarnation of the connection.  So you are unlikely to get here,
	 *  but if you do, drop the segment, and return.
	 */
	/* What does this `must have an ACK` mean? Just drop segment? */
discarded:
	free_pkb(pkb);
}

static void tcp_closed(struct tcp_sock *tsk, struct pkbuf *pkb,
			struct tcp_segment *seg)
{
	tcpsdbg("CLOSED");
	/*
	 * If closed, the connect may not call connect() or listen(),
	 * in which case it drops incoming packet and responds nothing.
	 * (see TCP/IP Illustrated Vol.2, tcp_input() L291-292)
	 */
	if (!tsk)
		tcp_send_reset(tsk, seg);
	free_pkb(pkb);
}

/*
 * OPEN CALL:
 * sent <SEQ=ISS><CTL=SYN>
 * SND.UNA = ISS, SND.NXT = ISS+1
 */
static void tcp_synsent(struct pkbuf *pkb, struct tcp_segment *seg,
			struct tcp_sock *tsk)
{
	struct tcp *tcphdr = seg->tcphdr;
	tcpsdbg("SYN-SENT");
	/* first check the ACK bit */
	tcpsdbg("1. check ack");
	if (tcphdr->ack) {
		/*
		 * Maybe we can reduce to `seg->ack != tsk->snd_nxt`
		 * Because we should not send data with the first SYN.
		 * (Just assert tsk->iss + 1 == tsk->snd_nxt)
		 */
		if (seg->ack <= tsk->iss || seg->ack > tsk->snd_nxt) {
			tcp_send_reset(tsk, seg);
			goto discarded;
		}
		/*
		 * RFC 793:
		 *   If SND.UNA =< SEG.ACK =< SND.NXT, the ACK is acceptable.
		 *   (Assert SND.UNA == 0)
		 */
	}
	/* second check the RST bit */
	tcpsdbg("2. check rst");
	if (tcphdr->rst) {
		if (tcphdr->ack) {
			/* connect closed port */
			tcpsdbg("Error:connection reset");
			tcp_set_state(tsk, TCP_CLOSED);
			if (tsk->wait_connect)
				wake_up(tsk->wait_connect);
			else
				tcpsdbg("No thread waiting for connection");
		}
		goto discarded;
	}
	/* third check the security and precedence (ignored) */
	tcpsdbg("3. No check the security and precedence");
	/* fouth check the SYN bit */
	tcpsdbg("4. check syn");
	if (tcphdr->syn) {
		tsk->irs = seg->seq;
		tsk->rcv_nxt = seg->seq + 1;
		if (tcphdr->ack)		/* No ack for simultaneous open */
			tsk->snd_una = seg->ack;	/* snd_una: iss -> iss+1 */
		/* delete retransmission queue which waits to be acknowledged */
		if (tsk->snd_una > tsk->iss) {	/* rcv.ack = snd.syn.seq+1 */
			tcp_set_state(tsk, TCP_ESTABLISHED);
			/* RFC 1122: error corrections of RFC 793 */
			tsk->snd_wnd = seg->wnd;
			tsk->snd_wl1 = seg->seq;
			tsk->snd_wl2 = seg->ack;
			/* reply ACK seq=snd.nxt, ack=rcv.nxt at right */
			tcp_send_ack(tsk, seg);
			tcpsdbg("Active three-way handshake successes!(SND.WIN:%d)", tsk->snd_wnd);
			wake_up(tsk->wait_connect);
			/*
			 * Data or controls which were queued for transmission
			 * may be included.  If there are other controls or text
			 * in the segment then continue processing at the sixth
			 * step * below where the URG bit is checked, otherwise
			 * return.
			 */
		} else {		/* simultaneous open */
			/* XXX: test */
			tcp_set_state(tsk, TCP_SYN_RECV);
			/* reply SYN+ACK seq=iss,ack=rcv.nxt */
			tcp_send_synack(tsk, seg);
			tcpsdbg("Simultaneous open(SYN-SENT => SYN-RECV)");
			/*
			 * queue text or other controls after established state
			 * has been reached
			 */
			return;
		}
	}
	/* fifth drop the segment and return */
	tcpsdbg("5. drop the segment");
discarded:
	free_pkb(pkb);
}

/* handle sock acccept queue when receiving ack in SYN-RECV state */
static int tcp_synrecv_ack(struct tcp_sock *tsk)
{
	/* FIXME: Maybe parent is dead. */
	if (tsk->parent->state != TCP_LISTEN)
		return -1;
	if (tcp_accept_queue_full(tsk->parent))
		return -1;
	tcp_accept_enqueue(tsk);
	tcpsdbg("Passive three-way handshake successes!");
	wake_up(tsk->parent->wait_accept);
	return 0;
}

static int seq_check(struct tcp_segment *seg, struct tcp_sock *tsk)
{
	unsigned int rcv_end = tsk->rcv_nxt + (tsk->rcv_wnd ?: 1);
	/* RFC 793:
	 * Segment Receive  Test
	 * Length  Window
	 * ------- -------  -------------------------------------------
	 *    0       0     SEG.SEQ = RCV.NXT
	 *    0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
	 *   >0       0     not acceptable
	 *   >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
	 *                  or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
	 */
	/* if len == 0, then lastseq == seq */
	if (seg->seq < rcv_end && tsk->rcv_nxt <= seg->lastseq)
		return 0;
	tcpsdbg("rcvnxt:%u <= seq:%u < rcv_end:%u",
		tsk->rcv_nxt, seg->seq, rcv_end);
	return -1;
}

static _inline void __tcp_update_window(struct tcp_sock *tsk,
					struct tcp_segment *seg)
{
		/* SND.WND is an offset from SND.UNA */
		tsk->snd_wnd = seg->wnd;
		tsk->snd_wl1 = seg->seq;
		tsk->snd_wl2 = seg->ack;
}

static _inline void tcp_update_window(struct tcp_sock *tsk,
					struct tcp_segment *seg)
{
	if ((tsk->snd_una <= seg->ack && seg->ack <= tsk->snd_nxt) &&
		(tsk->snd_wl1 < seg->seq ||
			(tsk->snd_wl1 == seg->seq && tsk->snd_wl2 <= seg->ack)))
		__tcp_update_window(tsk, seg);
}

/* Tcp state process method is implemented via RFC 793 #SEGMENT ARRIVE */
void tcp_process(struct pkbuf *pkb, struct tcp_segment *seg, struct sock *sk)
{
	struct tcp_sock *tsk = tcpsk(sk);
	struct tcp *tcphdr = seg->tcphdr;
	tcp_dbg_state(tsk);
	if (!tsk || tsk->state == TCP_CLOSED)
		return tcp_closed(tsk, pkb, seg);
	if (tsk->state == TCP_LISTEN)
		return tcp_listen(pkb, seg, tsk);
	if (tsk->state == TCP_SYN_SENT)
		return tcp_synsent(pkb, seg, tsk);
	if (tsk->state >= TCP_MAX_STATE)
		goto drop;
	/* first check sequence number */
	tcpsdbg("1. check seq");
	if (seq_check(seg, tsk) < 0) {
		/* incoming segment is not acceptable */
		if (!tcphdr->rst)
			tsk->flags |= TCP_F_ACKNOW; /*reply ACK seq=snd.nxt, ack=rcv.nxt*/
		goto drop;
	}
	/* second check the RST bit */
	tcpsdbg("2. check rst");
	if (tcphdr->rst) {
		/* abort a connection */
		switch (tsk->state) {
		case TCP_SYN_RECV:
			if (tsk->parent) {	/* passive open */
				tcp_unhash(&tsk->sk);
			} else {
				/*
				 * signal user "connection refused"
				 * when both users open simultaneously.
				 * XXX: test
				 */
				if (tsk->wait_connect)
					wake_up(tsk->wait_connect);
			}
			break;
		case TCP_ESTABLISHED:
		case TCP_FIN_WAIT1:
		case TCP_FIN_WAIT2:
		case TCP_CLOSE_WAIT:
			/* RECEIVE and SEND receive reset response */
			/* flush all segments queue */
			/* signal user "connection reset" */
			break;
		case TCP_CLOSING:
		case TCP_LAST_ACK:
		case TCP_TIME_WAIT:
			break;
		}
		tcp_set_state(tsk, TCP_CLOSED);
		tcp_unhash(&tsk->sk);
		tcp_unbhash(tsk);
		goto drop;
	}
	/* third check security and precedence (ignored) */
	tcpsdbg("3. NO check security and precedence");
	/* fourth check the SYN bit */
	tcpsdbg("4. check syn");
	if (tcphdr->syn) {
		/* only LISTEN and SYN-SENT can receive SYN */
		tcp_send_reset(tsk, seg);
		/* RECEIVE and SEND receive reset response */
		/* flush all segments queue */
		/* signal user "connection reset" */
		/*
		 * RFC 1122: error corrections of RFC 793:
		 * In SYN-RECEIVED state and if the connection was initiated
		 * with a passive OPEN, then return this connection to the
		 * LISTEN state and return.
		 * - We delete child tsk directly,
		 *   and its parent has been in LISTEN state.
		 */
		if (tsk->state == TCP_SYN_RECV && tsk->parent)
			tcp_unhash(&tsk->sk);
		tcp_set_state(tsk, TCP_CLOSED);
		free_sock(&tsk->sk);
	}
	/* fifth check the ACK field */
	tcpsdbg("5. check ack");
	/*
	 * RFC 793 say:
	 * 1. we should drop the segment and return
	 *    if the ACK bit is off.
	 * 2. Once in the ESTABLISHED state all segments must
	 *    carry current acknowledgment information.
	 * Should we do it ?
	 * -No for xinu
	 * -No for linux
	 */
	if (!tcphdr->ack)
		goto drop;
	switch (tsk->state) {
	case TCP_SYN_RECV:
		/*
		 * previous state LISTEN :
		 *  snd_nxt = iss + 1
		 *  snd_una = iss
		 * previous state SYN-SENT:
		 *  snd_nxt = iss+1
		 *  snd_una = iss
		 * Should we update snd_una to seg->ack here?
		 *  -Unknown for RFC 793
		 *  -Yes for xinu
		 *  -Yes for Linux
		 *  +Yes for tapip
		 * Are 'snd.una == seg.ack' right?
		 *  -Yes for RFC 793
		 *  -Yes for 4.4BSD-Lite
		 *  -Yes for xinu, although duplicate ACK
		 *  -Yes for Linux,
		 *  +Yes for tapip
		 */
		if (tsk->snd_una <= seg->ack && seg->ack <= tsk->snd_nxt) {
			if (tcp_synrecv_ack(tsk) < 0) {
				tcpsdbg("drop");
				goto drop;		/* Should we drop it? */
			}
			tsk->snd_una = seg->ack;
			/* RFC 1122: error corrections of RFC 793(SND.W**) */
			__tcp_update_window(tsk, seg);
			tcp_set_state(tsk, TCP_ESTABLISHED);
		} else {
			tcp_send_reset(tsk, seg);
			goto drop;
		}
		break;
	case TCP_ESTABLISHED:
	case TCP_CLOSE_WAIT:
	case TCP_LAST_ACK:
	case TCP_FIN_WAIT1:
	case TCP_CLOSING:
		tcpsdbg("SND.UNA %u < SEG.ACK %u <= SND.NXT %u",
				tsk->snd_una, seg->ack, tsk->snd_nxt);
		if (tsk->snd_una < seg->ack && seg->ack <= tsk->snd_nxt) {
			tsk->snd_una = seg->ack;
			/*
			 * remove any segments on the restransmission
			 * queue which are thereby entirely acknowledged
			 */
			if (tsk->state == TCP_FIN_WAIT1) {
				tcp_set_state(tsk, TCP_FIN_WAIT2);
			} else if (tsk->state == TCP_CLOSING) {
				tcp_set_timewait_timer(tsk);
				goto drop;
			} else if (tsk->state == TCP_LAST_ACK) {
				tcp_set_state(tsk, TCP_CLOSED);
				tcp_unhash(&tsk->sk);
				/* for tcp active open */
				tcp_unbhash(tsk);
				goto drop;
			}
		} else if (seg->ack > tsk->snd_nxt) {	/* something not yet sent */
			/* reply ACK ack = ? */
			goto drop;
		} else if (seg->ack <= tsk->snd_una) {	/* duplicate ACK */
			/*
			 * RFC 793 say we can ignore duplicate ACK.
			 * What does `ignore` mean?
			 * Should we conitnue and not drop segment ?
			 * -Yes for xinu
			 * -Yes for linux
			 * -Yes for 4.4BSD-Lite
			 * +Yes for tapip
			 *
			 * After three-way handshake connection is established,
			 * then SND.UNA == SND.NXT, which means next remote
			 * packet ACK is always duplicate. Although this
			 * happens frequently, we should not view it as an
			 * error.
			 *
			 * Close simultaneously in FIN_WAIT1 also causes this.
			 *
			 * Also window update packet will cause this situation.
			 */
		}
		tcp_update_window(tsk, seg);
		break;
	case TCP_FIN_WAIT2:
	/*
          In addition to the processing for the ESTABLISHED state, if
          the retransmission queue is empty, the user's CLOSE can be
          acknowledged ("ok") but do not delete the TCB. (wait FIN)
	 */
		break;
	case TCP_TIME_WAIT:
	/*
          The only thing that can arrive in this state is a
          retransmission of the remote FIN.  Acknowledge it, and restart
          the 2 MSL timeout.
	 */
		break;
	}

	/* sixth check the URG bit */
	tcpsdbg("6. check urg");
	if (tcphdr->urg) {
		switch (tsk->state) {
		case TCP_ESTABLISHED:
		case TCP_FIN_WAIT1:
		case TCP_FIN_WAIT2:
	/*
        If the URG bit is set, RCV.UP <- max(RCV.UP,SEG.UP), and signal
        the user that the remote side has urgent data if the urgent
        pointer (RCV.UP) is in advance of the data consumed.  If the
        user has already been signaled (or is still in the "urgent
        mode") for this continuous sequence of urgent data, do not
        signal the user again.
	 */
			break;
		case TCP_CLOSE_WAIT:
		case TCP_CLOSING:
		case TCP_LAST_ACK:
		case TCP_TIME_WAIT:
			/* ignore */
			/* Should we conitnue or drop? */
			break;
		case TCP_SYN_RECV:
			/* ?? */
			break;
		}
	}
	/* seventh process the segment text */
	tcpsdbg("7. segment text");
	switch (tsk->state) {
	case TCP_ESTABLISHED:
	case TCP_FIN_WAIT1:
	case TCP_FIN_WAIT2:
		if (tcphdr->psh || seg->dlen > 0)
			tcp_recv_text(tsk, seg, pkb);
		break;
	/*
	 * CLOSE-WAIT|CLOSING|LAST-ACK|TIME-WAIT:
	 *  FIN has been received, so we ignore the segment text.
	 *
	 * OTHER STATES: segment is ignored!
	 */
	}
	/* eighth check the FIN bit */
	tcpsdbg("8. check fin");
	if (tcphdr->fin) {
		switch (tsk->state) {
		case TCP_SYN_RECV:
			/*
			 * SYN-RECV means remote->local connection is established
			 * see TCP/IP Illustrated Vol.2, tcp_input() L1127-1134
			 */
		case TCP_ESTABLISHED:
			/* waiting user to close */
			tcp_set_state(tsk, TCP_CLOSE_WAIT);
			tsk->flags |= TCP_F_PUSH;
			tsk->sk.ops->recv_notify(&tsk->sk);
			break;
		case TCP_FIN_WAIT1:
			/* both users close simultaneously */
			tcp_set_state(tsk, TCP_CLOSING);
			break;
		case TCP_CLOSE_WAIT:	/* Remain in the CLOSE-WAIT state */
		case TCP_CLOSING:	/* Remain in the CLOSING state */
		case TCP_LAST_ACK:	/* Remain in the LAST-ACK state */
			/* dont handle it, must be duplicate FIN */
			break;
		case TCP_TIME_WAIT:	/* Remain in the TIME-WAIT state */
			/* restart the 2 MSL time-wait timeout */
			tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
			break;
		case TCP_FIN_WAIT2:
			/* FIXME: turn off the other timers. */
			tcp_set_timewait_timer(tsk);
			break;
		}
		/* singal the user "connection closing" */
		/* return any pending RECEIVEs with same message */
		/* advance rcv.nxt over fin */
		tsk->rcv_nxt = seg->seq + 1;
		/* send ACK for FIN */
		tsk->flags |= TCP_F_ACKNOW;
		/*
		 * FIN implies PUSH for any segment text not yet delivered
		 * to the user.
		 */
	}
drop:
	/* TODO: use ack delay timer instead of sending ack now */
	if (tsk->flags & (TCP_F_ACKNOW|TCP_F_ACKDELAY))
		tcp_send_ack(tsk, seg);
	free_pkb(pkb);
}

