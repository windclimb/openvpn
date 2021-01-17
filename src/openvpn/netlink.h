#ifndef OVPN_NETLINK_H
#define OVPN_NETLINK_H

#include <linux/types.h>
#include <linux/netlink.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "ovpn_dco.h"

#define KEY_LEN (256 / 8)
#define NONCE_LEN 8

struct context;
struct nl_ctx;

struct ovpn_ctx {
	__u8 key_enc[KEY_LEN];
	__u8 key_dec[KEY_LEN];
	__u8 nonce_enc[NONCE_LEN];
	__u8 nonce_dec[NONCE_LEN];

	enum ovpn_cipher_alg cipher;

	sa_family_t sa_family;

	__u16 lport;

	union {
		struct sockaddr_in in4;
		struct sockaddr_in6 in6;
	} remote;
	socklen_t socklen;

	unsigned int ifindex;

	int socket;

	__u32 keepalive_interval;
	__u32 keepalive_timeout;

	__u8 data_format;

	struct nl_ctx *nl_ctx;
};

int netlink_dco_start_udp4_vpn(struct ovpn_ctx *ovpn, const int sd);
int netlink_dco_new_peer(struct ovpn_ctx *ovpn);
int netlink_dco_set_peer(struct ovpn_ctx *ovpn);
int netlink_dco_new_key(struct ovpn_ctx *ovpn, const uint32_t peer_id, const uint16_t key_id, enum ovpn_key_slot slot);

void netlink_dco_cleanup_context(struct context *c);
void *netlink_dco_register(struct ovpn_ctx *ovpn, struct context *c);

void netlink_dco_process(struct context *c);

#endif /* OVPN_NETLINK_H */
