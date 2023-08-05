int netlinkd_delete_tunnel(const char *tnlname);

int netlinkd_create_6in4(
	const char *tnlname,
	const char *ifmaster,
	unsigned int saddr,
	unsigned int daddr
);

int netlinkd_create_4in6(
	const char *tnlname,
	const char *ifmaster,
	const unsigned char saddr[16],
	const unsigned char daddr[16]
);
