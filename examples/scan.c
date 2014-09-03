#include <arpscan.h>

static int
_cb_discover(struct arpscan *scan, char *iface, struct addr *ip, struct addr *ether)
{
	printf("%s: %s (%s)\n", iface, addr_ntoa(ip), addr_ntoa(ether));
	return 0;
}

static void
_cb_done(struct arpscan *scan)
{
	event_base_loopbreak(scan->evb);
}

int
main(void)
{
	struct event_base *evb;
	struct arpscan *scan;

	evb = event_base_new();
	scan = arpscan_new(evb, "any", ARPSCAN_HARSHNESS_MAX, ARPSCAN_SEND_ONCE,
		ARPSCAN_FINALWAIT_2SEC, ARPSCAN_VERBOSE, NULL, _cb_discover, _cb_done);

	event_base_dispatch(evb);
	arpscan_free(scan);
	return 0;
}
