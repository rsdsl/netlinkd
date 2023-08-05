#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_tunnel.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int netlinkd_delete_tunnel(const char *tnlname)
{
	struct ip_tunnel_parm p;

	strcpy(p.name, tnlname);

	struct ifreq ifr;

	strcpy(ifr.ifr_name, tnlname);
	ifr.ifr_ifru.ifru_data = (char *) &p;

	int fd;
	if ((fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		return -1;
	}

	if (ioctl(fd, SIOCDELTUNNEL, &ifr)) {
		return -1;
	}

	close(fd);
	return 0;
}

int netlinkd_create_6in4(
	const char *tnlname,
	const char *ifmaster,
	unsigned int saddr,
	unsigned int daddr
)
{
	struct ip_tunnel_parm p;

	strcpy(p.name, tnlname);
	p.iph.version = 4;
	p.iph.ihl = 5;
	p.iph.protocol = IPPROTO_IPV6;
	p.iph.saddr = saddr;
	p.iph.daddr = daddr;
	p.link = if_nametoindex(ifmaster);

	if (!p.link) {
		return -1;
	}

	struct ifreq ifr;

	strcpy(ifr.ifr_name, "sit0");
	ifr.ifr_ifru.ifru_data = (char *) &p;

	int fd;
	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		return -1;
	}

	if (ioctl(fd, SIOCADDTUNNEL, &ifr)) {
		return -1;
	}

	close(fd);
	return 0;
}

int netlinkd_create_4in6(
	const char *tnlname,
	const char *ifmaster,
	const unsigned char saddr[16],
	const unsigned char daddr[16]
)
{
	struct ip_tunnel_parm p;

	strcpy(p.name, tnlname);
	p.iph.version = 0;
	p.iph.ihl = 0;
	p.iph.protocol = IPPROTO_IP;
	p.iph.saddr = saddr[0];
	p.iph.daddr = daddr[0];
	p.link = if_nametoindex(ifmaster);

	if (!p.link) {
		return -1;
	}

	struct ifreq ifr;

	strcpy(ifr.ifr_name, "ip6tnl0");
	ifr.ifr_ifru.ifru_data = (char *) &p;

	int fd;
	if ((fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		return -1;
	}

	if (ioctl(fd, SIOCADDTUNNEL, &ifr)) {
		return -1;
	}

	close(fd);
	return 0;
}
