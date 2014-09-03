/* libarpscan - ARP scan library in C */
/* Copyright (c) 2014 Laurent Ghigonis <laurent@gouloum.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event.h>
#include <dnet.h>
#include <pcapev.h>

#define ARPSCAN_HARSHNESS_SLOW 1
#define ARPSCAN_HARSHNESS_NORMAL 20
#define ARPSCAN_HARSHNESS_FAST 100
#define ARPSCAN_HARSHNESS_MAX 1000000
#define ARPSCAN_SEND_ONCE 1
#define ARPSCAN_SEND_TWICE 2
#define ARPSCAN_FINALWAIT_2SEC 2
#define ARPSCAN_VERBOSE 1
#define ARPSCAN_NOVERBOSE 0

// extern struct arpscan_iface; /* internal */

struct arpscan {
	struct event_base *evb;
	char *iface;
	int harshness;
	struct timeval harshness_tv;
	int send_repeat;
	int verbose;
	struct pcapev *cap;
	int cap_created;
	int (*cbusr_discover)(struct arpscan *, char *, struct addr *, struct addr *);
	void (*cbusr_done)(struct arpscan *);
	LIST_HEAD(, arpscan_iface) ifaces;
	struct event *ev_done;
	struct timeval done_tv;
};

struct arpscan *arpscan_new(struct event_base *evb, char *iface, int harshness, int send_repeat, int final_wait, int verbose, struct pcapev *cap,
	int (*cbusr_discover)(struct arpscan *, char *, struct addr *, struct addr *),
	void (*cbusr_done)(struct arpscan *));

void   arpscan_free(struct arpscan *);
