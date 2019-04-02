#include <gettext.h>
#include <config.h>
#include <libtun6/tun6.h>
#include <libteredo/teredo.h>
#include <libteredo/tunnel.h>
#include <fcntl.h>
#include <err.h>
#include <assert.h>
#include <errno.h>
#include <privproc.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stdlib.h>

struct miredo_tunnel {
	tun6 *tunnel;
	int priv_fd;
	int icmp6_fd;
};

static void miredo_recv_callback(void *data, const void *packet, size_t length)
{
	assert(data != NULL);
	(void)tun6_send (((struct miredo_tunnel *)data)->tunnel, packet, length);
}

static void miredo_icmp6_callback(void *data, const void *packet, size_t length, const struct in6_addr *dst)
{
	assert(data != NULL);
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = *dst
	};
	(void)sendto(((struct miredo_tunnel *)data)->icmp6_fd, packet, length, 0, (struct sockaddr *)&addr, sizeof (addr));
}


static int configure_tunnel(int fd, const struct in6_addr *addr, unsigned mtu)
{
	if (mtu > 65535) {
		errno = EINVAL;
		return -1;
	}
	struct miredo_tunnel_settings s = {
		.addr = {},
		.mtu = (uint16_t) mtu,
	};
	memcpy (&s.addr, addr, sizeof (s.addr));

	int res;
	if ((send (fd, &s, sizeof (s), MSG_NOSIGNAL) != sizeof (s))
	 || (recv (fd, &res, sizeof (res), MSG_WAITALL) != sizeof (res)))
		return -1;

	return res;
}

static void miredo_up_callback (void *data, const struct in6_addr *addr, uint16_t mtu)
{
	char str[INET6_ADDRSTRLEN];
	warnx("Teredo pseudo-tunnel started");
	if (inet_ntop (AF_INET6, addr, str, sizeof (str)) != NULL)
		warnx(" (address: %s, MTU: %"PRIu16")", str, mtu);

	assert(data != NULL);
	configure_tunnel(((struct miredo_tunnel *)data)->priv_fd, addr, mtu);
}

static void miredo_down_callback (void *data)
{
	assert(data != NULL);
	configure_tunnel(((struct miredo_tunnel *)data)->priv_fd, &in6addr_any, 1280);
	warnx("Teredo pseudo-tunnel stopped");
}

static int setup_icmp6_socket(void)
{
	int fd = socket(AF_INET6, SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC, IPPROTO_ICMPV6);
	if (fd < 0)
		err(1, "socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)");
	/* We don't use the socket for receive -> block all */
	struct icmp6_filter filt;
	ICMP6_FILTER_SETBLOCKALL (&filt);
	if (setsockopt(fd, SOL_ICMPV6, ICMP6_FILTER, &filt, sizeof (filt)) < 0)
		err(1, "setsockopt(fd, SOL_ICMPV6, ICMP6_FILTER, filt)");
	return fd;
}


struct options {
	int teredo_fd;
	int tun_fd;
	int req_fd;
	int privproc_fd;
	char *server_name;
	char *server_name2;
};

static int parse_fd(char *str)
{
	char *end;
	errno = 0;
	const int fd = strtol(str, &end, 0);
	if (errno != 0) err(1, "strtol(%s)", str);
	if (str == end) errx(1, "strtol found no digits in %s", str);
	if (fcntl(fd, F_GETFD) < 0) err(1, "fcntl(%d, F_GETFD)", fd);
	return fd;
}

static struct options parse_args(int argc, char **argv)
{
	if (argc != 7) {
		errx(1, "Usage: %s <teredo_fd> <tun_fd> <req_fd> <privproc_fd> <server_name> <server_name2>",
		     argc > 0 ? argv[0] : "miredo-run-client");
	}
	return (struct options) {
		.teredo_fd = parse_fd(argv[1]),
		.tun_fd = parse_fd(argv[2]),
		.req_fd = parse_fd(argv[3]),
		.privproc_fd = parse_fd(argv[4]),
		.server_name = argv[5],
		.server_name2 = argv[6],
	};
}

int main(int argc, char **argv)
{
	struct options opt = parse_args(argc, argv);
	if (teredo_startup(true)) err(1, "teredo_startup(True)");
	teredo_tunnel *relay = teredo_create_from_fd(opt.teredo_fd);
	if (!relay) errx(1, "failed to create teredo relay from fd %d", opt.teredo_fd);
	tun6 *tunnel = tun6_create_from_fd(opt.tun_fd, opt.req_fd);
	if (!tunnel) errx(1, "failed to create tun object from fd %d", opt.tun_fd);
	int ret = teredo_set_client_mode(relay, opt.server_name, opt.server_name2);
	if (ret) errx(1, "failed to set up teredo client");
	int icmp6_fd = setup_icmp6_socket();

	struct miredo_tunnel data = { tunnel, opt.privproc_fd, icmp6_fd };
	teredo_set_privdata(relay, &data);
	teredo_set_state_cb(relay, miredo_up_callback, miredo_down_callback);
	teredo_set_recv_callback(relay, miredo_recv_callback);
	teredo_set_icmpv6_callback(relay, miredo_icmp6_callback);
	if (teredo_run_async(relay)) errx(1, "failed to start teredo tunnel thread");
	for (;;) {
		/* Handle incoming data */
		struct {
			struct ip6_hdr ip6;
			uint8_t fill[65467];
		} pbuf;

		/* Forwards IPv6 packet to Teredo (Packet transmission) */
		int val = tun6_wait_recv(tunnel, &pbuf.ip6, sizeof (pbuf));
		if (val >= 40) {
			teredo_transmit (relay, &pbuf.ip6, val);
		}
	}
	return 0;
}
