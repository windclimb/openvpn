#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#include <linux/socket.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>

#include "error.h"
#include "netlink.h"

#include <netlink/socket.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>

#define nla_nest_start(_msg, _type) \
	nla_nest_start(_msg, (_type) | NLA_F_NESTED)

typedef int (*ovpn_nl_cb)(struct nl_msg *msg, void *arg);

struct nl_ctx {
	struct nl_sock *nl_sock;
	struct nl_msg *nl_msg;
	struct nl_cb *nl_cb;

	int ovpn_dco_id;
};

static struct nl_ctx *nl_ctx_alloc(struct ovpn_ctx *ovpn,
				   enum ovpn_nl_commands cmd)
{
	struct nl_ctx *ctx;
	int ret;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->nl_sock = nl_socket_alloc();
	if (!ctx->nl_sock) {
		fprintf(stderr, "cannot allocate netlink socket\n");
		goto err_free;
	}

	nl_socket_set_buffer_size(ctx->nl_sock, 8192, 8192);

	ret = genl_connect(ctx->nl_sock);
	if (ret) {
		fprintf(stderr, "cannot connect to generic netlink: %s\n",
			nl_geterror(ret));
		goto err_sock;
	}

	ctx->ovpn_dco_id = genl_ctrl_resolve(ctx->nl_sock, OVPN_NL_NAME);
	if (ctx->ovpn_dco_id < 0) {
		fprintf(stderr, "cannot find ovpn_dco netlink component: %d\n",
			ctx->ovpn_dco_id);
		goto err_free;
	}

	ctx->nl_msg = nlmsg_alloc();
	if (!ctx->nl_msg) {
		fprintf(stderr, "cannot allocate netlink message\n");
		goto err_sock;
	}

	ctx->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!ctx->nl_cb) {
		fprintf(stderr, "failed to allocate netlink callback\n");
		goto err_msg;
	}

	nl_socket_set_cb(ctx->nl_sock, ctx->nl_cb);

	genlmsg_put(ctx->nl_msg, 0, 0, ctx->ovpn_dco_id, 0, 0, cmd, 0);
	NLA_PUT_U32(ctx->nl_msg, OVPN_ATTR_IFINDEX, ovpn->ifindex);

	return ctx;
nla_put_failure:
err_msg:
	nlmsg_free(ctx->nl_msg);
err_sock:
	nl_socket_free(ctx->nl_sock);
err_free:
	free(ctx);
	return NULL;
}

static void nl_ctx_free(struct nl_ctx *ctx)
{
	if (!ctx)
		return;

	nl_socket_free(ctx->nl_sock);
	nlmsg_free(ctx->nl_msg);
	nl_cb_put(ctx->nl_cb);
	free(ctx);
}


static int ovpn_nl_cb_error(struct sockaddr_nl (*nla)__attribute__((unused)),
			    struct nlmsgerr *err, void *arg)
{
	return NL_STOP;
}

static int ovpn_nl_cb_finish(struct nl_msg (*msg)__attribute__((unused)),
			     void *arg)
{
	int *status = arg;

	*status = 0;
	return NL_SKIP;
}

static int ovpn_nl_recvmsgs(struct nl_ctx *ctx)
{
	int ret;

	ret = nl_recvmsgs(ctx->nl_sock, ctx->nl_cb);

	switch (ret) {
	case -NLE_INTR:
		fprintf(stderr,
			"netlink received interrupt due to signal - ignoring\n");
		break;
	case -NLE_NOMEM:
		fprintf(stderr, "netlink out of memory error\n");
		break;
	case -NLE_AGAIN:
		fprintf(stderr,
			"netlink reports blocking read - aborting wait\n");
		break;
	default:
		if (ret)
			fprintf(stderr, "netlink reports error (%d): %s\n",
				ret, nl_geterror(-ret));
		break;
	}

	return ret;
}

static int ovpn_nl_msg_send(struct nl_ctx *ctx, ovpn_nl_cb cb)
{
	int status = 1;

	nl_cb_err(ctx->nl_cb, NL_CB_CUSTOM, ovpn_nl_cb_error, &status);
	nl_cb_set(ctx->nl_cb, NL_CB_FINISH, NL_CB_CUSTOM, ovpn_nl_cb_finish,
		  &status);
	nl_cb_set(ctx->nl_cb, NL_CB_ACK, NL_CB_CUSTOM, ovpn_nl_cb_finish,
		  &status);

	if (cb)
		nl_cb_set(ctx->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, cb, ctx);

	nl_send_auto_complete(ctx->nl_sock, ctx->nl_msg);

	while (status == 1)
		ovpn_nl_recvmsgs(ctx);

	if (status < 0)
		fprintf(stderr, "failed to send netlink message: %s (%d)\n",
			strerror(-status), status);

	return status;
}

int netlink_dco_start_udp4_vpn(struct ovpn_ctx *ovpn, const int sd)
{
	msg(D_HANDSHAKE, "start vpn");

	struct nl_ctx *ctx;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_START_VPN);
	if (!ctx)
		return -ENOMEM;

	NLA_PUT_U32(ctx->nl_msg, OVPN_ATTR_SOCKET, sd);
	NLA_PUT_U8(ctx->nl_msg, OVPN_ATTR_PROTO, OVPN_PROTO_UDP4);
	NLA_PUT_U8(ctx->nl_msg, OVPN_ATTR_MODE, OVPN_MODE_CLIENT);

	ovpn_nl_msg_send(ctx, NULL);
	msg(D_HANDSHAKE, "start vpn ok");

nla_put_failure:
	nl_ctx_free(ctx);

	return 0;
}

int netlink_dco_new_peer(struct ovpn_ctx *ovpn)
{
	msg(D_HANDSHAKE, "new peer");

	struct nl_ctx *ctx;
	size_t alen = sizeof(struct sockaddr_in);

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_NEW_PEER);
	if (!ctx)
		return -ENOMEM;

	NLA_PUT(ctx->nl_msg, OVPN_ATTR_SOCKADDR_REMOTE, alen, &ovpn->remote);

	ovpn_nl_msg_send(ctx, NULL);
	msg(D_HANDSHAKE, "new peer ok");

nla_put_failure:
	nl_ctx_free(ctx);

	return 0;
}

int netlink_dco_new_key(struct ovpn_ctx *ovpn, const uint32_t peer_id, const uint16_t key_id)
{
	msg(D_HANDSHAKE, "new key");
	struct nlattr *key_dir;
	struct nl_ctx *ctx;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_NEW_KEY);
	if (!ctx)
		return -ENOMEM;

	NLA_PUT_U32(ctx->nl_msg, OVPN_ATTR_REMOTE_PEER_ID, peer_id);
	NLA_PUT_U8(ctx->nl_msg, OVPN_ATTR_KEY_SLOT, OVPN_KEY_SLOT_PRIMARY);
	NLA_PUT_U16(ctx->nl_msg, OVPN_ATTR_KEY_ID, key_id);

	NLA_PUT_U16(ctx->nl_msg, OVPN_ATTR_CIPHER_ALG, ovpn->cipher);

	key_dir = nla_nest_start(ctx->nl_msg, OVPN_ATTR_ENCRYPT_KEY);
	NLA_PUT(ctx->nl_msg, OVPN_KEY_DIR_ATTR_CIPHER_KEY, KEY_LEN, ovpn->key_enc);
	NLA_PUT(ctx->nl_msg, OVPN_KEY_DIR_ATTR_NONCE_TAIL, NONCE_LEN, ovpn->nonce_enc);
	nla_nest_end(ctx->nl_msg, key_dir);

	key_dir = nla_nest_start(ctx->nl_msg, OVPN_ATTR_DECRYPT_KEY);
	NLA_PUT(ctx->nl_msg, OVPN_KEY_DIR_ATTR_CIPHER_KEY, KEY_LEN, ovpn->key_dec);
	NLA_PUT(ctx->nl_msg, OVPN_KEY_DIR_ATTR_NONCE_TAIL, NONCE_LEN, ovpn->nonce_dec);
	nla_nest_end(ctx->nl_msg, key_dir);

	ovpn_nl_msg_send(ctx, NULL);
	msg(D_HANDSHAKE, "new key ok");

nla_put_failure:
	nl_ctx_free(ctx);

	return 0;
}
