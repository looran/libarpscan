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

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "arpscan.h"

#define LOG(x, ...) printf(x, ##__VA_ARGS__)
#define LOG_VERBOSE(x, ...) if (scan->verbose) printf(x, ##__VA_ARGS__);

struct __attribute__((packed)) xarpreq {
	struct __attribute__((packed)) {
		uint8_t dst_mac[6];
		uint8_t src_mac[6];
		uint16_t ethertype;
	} eth;
	struct __attribute__((packed)) {
		uint16_t type_hardware;
		uint16_t type_proto;
		uint8_t size_hardware;
		uint8_t size_proto;
		uint16_t opcode;
		uint8_t src_mac[6];
		uint32_t src_ip;
		uint8_t dst_mac[6];
		uint32_t dst_ip;
	} arp;
};

struct arpscan_iface {
	LIST_ENTRY(arpscan_iface) entry;
	struct arpscan *scan;
	struct event *ev_timer;
	eth_t *eth;
	struct xarpreq *req;
	struct {
		uint32_t start;
		uint32_t end;
		uint32_t cur;
	} dst_ip;
};

static int _cb_intf_loop(const struct intf_entry *, void *);
static void _cb_scan_done(evutil_socket_t, short, void *);
static int _cb_arp(struct pcapev *, struct arphdr *, int, struct ether_header *, void *);
static void _scaniface_start(struct arpscan *, const struct intf_entry *);
static void _scaniface_free(struct arpscan_iface *);
static void _cb_iface_send(evutil_socket_t, short, void *);
static struct xarpreq *_xarpreq_new(eth_t *, uint32_t);

struct arpscan *
arpscan_new(struct event_base *evb, char *iface, int harshness, int send_repeat, int final_wait, int verbose, struct pcapev *cap,
	int (*cbusr_discover)(struct arpscan *, char *, struct addr *, struct addr *),
	void (*cbusr_done)(struct arpscan *))
{
	struct arpscan *scan;
	intf_t *intf;

	scan = calloc(1, sizeof(struct arpscan));
	scan->evb = evb;
	if (cap) {
		scan->cap = cap;
	} else {
		scan->cap = pcapev_new(evb, iface, PCAPEV_SNAPLEN_DEFAULT, PCAPEV_NOPROMISC, PCAPEV_NOFILTER, PCAPEV_NOVERBOSE);
		scan->cap_created = 1;
	}
	scan->iface = iface;
	scan->harshness = harshness;
	scan->harshness_tv.tv_sec = 0;
	scan->harshness_tv.tv_usec = 1000000 / harshness;
	scan->send_repeat = send_repeat;
	scan->verbose = verbose;
	scan->cbusr_discover = cbusr_discover;
	scan->cbusr_done = cbusr_done;
	scan->done_tv.tv_sec = final_wait;
	scan->done_tv.tv_usec = 0;

	pcapev_addcb_arp(scan->cap, _cb_arp, scan);
	pcapev_start(scan->cap);

	intf = intf_open();
	intf_loop(intf, _cb_intf_loop, scan);

	if (LIST_EMPTY(&scan->ifaces))
		goto err;

	return scan;

err:
	arpscan_free(scan);
	return NULL;
}

void
arpscan_free(struct arpscan *scan)
{
	struct arpscan_iface *scanif;

	LIST_FOREACH(scanif, &scan->ifaces, entry) {
		_scaniface_free(scanif);
	}
	if (scan->cap_created)
		pcapev_free(scan->cap);
	free(scan);
}

static int
_cb_intf_loop(const struct intf_entry *entry, void *arg)
{
	struct arpscan *scan;

	scan = arg;
	if (!strcmp(entry->intf_name, "lo"))
		return 0;
	if (!strcmp(scan->iface, "any") || !strcmp(entry->intf_name, scan->iface))
		_scaniface_start(scan, entry);

	return 0;
}

static void
_cb_scan_done(evutil_socket_t fd, short what, void *arg)
{
	struct arpscan *scan;

	scan = arg;
	scan->cbusr_done(scan);
}

static int
_cb_arp(struct pcapev *cap, struct arphdr *arp, int len, struct ether_header *ether, void *arg)
{
	struct arpscan *scan;
	struct addr sender_ip;
	struct addr sender_ether;

	scan = arg;
	if (ntohs(arp->ar_op) != ARPOP_REPLY)
		return 0;
	if (len < (sizeof(struct arphdr) + 6 + 4 + 6 + 4)) {
		LOG_VERBOSE("_cb_arp: len < (sizeof(struct arphdr) + 6 + 4 + 6 + 4) ! (%x)\n", len);
		return 0;
	}
	if (ntohs(arp->ar_hrd) != 0x1) {
		LOG_VERBOSE("_cb_arp: ar_hdr not ethernet !\n");
		return 0;
	}
	if (ntohs(arp->ar_pro) != 0x800) {
		LOG_VERBOSE("_cb_arp: ar_pro not IP !\n");
		return 0;
	}
	if (arp->ar_hln != 0x6) {
		LOG_VERBOSE("_cb_arp: ar_hln not 6 !\n");
		return 0;
	}
	if (arp->ar_pln != 0x4) {
		LOG_VERBOSE("_cb_arp: ar_pln not 4 !\n");
		return 0;
	}
	bzero(&sender_ether, sizeof(struct addr));
	sender_ether.addr_type = ADDR_TYPE_ETH;
	sender_ether.addr_bits = 32; // XXX
	memcpy(&sender_ether.addr_eth.data, (uint32_t *)((u_char *)arp + sizeof(struct arphdr)), 6);
	bzero(&sender_ip, sizeof(struct addr));
	sender_ip.addr_type = ADDR_TYPE_IP;
	sender_ip.addr_bits = 24; // XXX
	sender_ip.addr_ip = *(uint32_t *)((u_char *)arp + sizeof(struct arphdr) + arp->ar_hln);
	
	scan->cbusr_discover(scan, NULL, &sender_ip, &sender_ether);
	return 0;
}

static void
_scaniface_start(struct arpscan *scan, const struct intf_entry *intf)
{
	struct arpscan_iface *scanif;
	uint32_t myip;
	uint16_t mymask;

	LOG_VERBOSE("_scaniface_start: %s\n", intf->intf_name);
	scanif = calloc(1, sizeof(struct arpscan_iface));
	scanif->scan = scan;
	scanif->eth = eth_open(intf->intf_name);
	scanif->req = _xarpreq_new(scanif->eth, intf->intf_addr.addr_ip);

	myip = ntohl(intf->intf_addr.addr_ip);// ^ (uint32_t 0xffffff00;
	mymask = intf->intf_addr.addr_bits;
	printf("myip : %x\n", myip);
	printf("mymask: %d\n", mymask);
	scanif->dst_ip.start = (myip >> (32-mymask)) << (32-mymask);
	scanif->dst_ip.end = (~(0xffffffff << (32-mymask)) | scanif->dst_ip.start);
	scanif->dst_ip.cur = scanif->dst_ip.start;
	printf("start: %x\n", scanif->dst_ip.start);
	printf("end  : %x\n", scanif->dst_ip.end);
	printf("cur  : %x\n", scanif->dst_ip.cur);

	scanif->ev_timer = evtimer_new(scan->evb, _cb_iface_send, scanif);
	evtimer_add(scanif->ev_timer, &scan->harshness_tv);
	LIST_INSERT_HEAD(&scan->ifaces, scanif, entry);
}

static void
_scaniface_free(struct arpscan_iface *scanif)
{
	struct arpscan *scan;

	scan = scanif->scan;
	LOG_VERBOSE("_scaniface_free\n");
	eth_close(scanif->eth);
	evtimer_del(scanif->ev_timer);
	free(scanif);
}

static void
_cb_iface_send(evutil_socket_t fd, short what, void *arg)
{
	struct arpscan_iface *scanif;
	struct arpscan *scan;
	int i;

	scanif = arg;
	scan = scanif->scan;

	scanif->req->arp.dst_ip = htonl(scanif->dst_ip.cur);
	for (i=0; i<scan->send_repeat; i++)
		eth_send(scanif->eth, scanif->req, sizeof(struct xarpreq));
	if (scanif->dst_ip.cur == scanif->dst_ip.end) {
		LIST_REMOVE(scanif, entry);
		_scaniface_free(scanif);
		if (LIST_EMPTY(&scan->ifaces)) {
			scan->ev_done = evtimer_new(scan->evb, _cb_scan_done, scan);
			evtimer_add(scan->ev_done, &scan->done_tv);
		}
		return;
	}
	scanif->dst_ip.cur += 1;

	evtimer_add(scanif->ev_timer, &scan->harshness_tv);
}

static struct xarpreq *
_xarpreq_new(eth_t *eth, uint32_t src_ip)
{
	struct xarpreq *req;
	struct eth_addr src_mac;

	eth_get(eth, &src_mac);

	req = malloc(sizeof (struct xarpreq));
	memcpy(req->eth.dst_mac, "\xff\xff\xff\xff\xff\xff", sizeof(req->eth.dst_mac));
	memcpy(req->eth.src_mac, src_mac.data, sizeof(req->eth.src_mac));
	req->eth.ethertype = htons(0x806);
	req->arp.type_hardware = htons(0x1);
	req->arp.type_proto = htons(0x800);
	req->arp.size_hardware = 0x6;
	req->arp.size_proto = 0x4;
	req->arp.opcode = htons(0x1);
	memcpy(req->arp.src_mac, src_mac.data, sizeof(req->arp.src_mac));
	req->arp.src_ip = src_ip;
	memcpy(req->arp.dst_mac, "\x00\x00\x00\x00\x00\x00", sizeof(req->arp.dst_mac));
	req->arp.dst_ip = 0x0;

	return req;
}

