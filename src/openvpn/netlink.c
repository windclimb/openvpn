#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"
#include "openvpn.h"
#include "ping.h"

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

#include <ndm/time.h>

#define KEYS_SWAP_INTERVAL_		10 /* seconds */

#define nla_nest_start(_msg, _type) \
	nla_nest_start(_msg, (_type) | NLA_F_NESTED)

typedef int (*ovpn_nl_cb)(struct nl_msg *msg, void *arg);

struct nl_ctx {
	struct nl_sock *nl_sock;
	struct nl_msg *nl_msg;
	struct nl_cb *nl_cb;
	struct context *c;

	int ovpn_dco_id;
	struct timespec key_install_time;
	int ovpn_dco_ifindex;
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
		msg(D_HANDSHAKE, "cannot allocate netlink socket");
		goto err_free;
	}

	nl_socket_set_buffer_size(ctx->nl_sock, 8192, 8192);

	ret = genl_connect(ctx->nl_sock);
	if (ret) {
		msg(D_HANDSHAKE, "cannot connect to generic netlink: %s",
			nl_geterror(ret));
		goto err_sock;
	}

	ctx->ovpn_dco_id = genl_ctrl_resolve(ctx->nl_sock, OVPN_NL_NAME);
	if (ctx->ovpn_dco_id < 0) {
		msg(D_HANDSHAKE, "cannot find ovpn_dco netlink component: %d",
			ctx->ovpn_dco_id);
		goto err_free;
	}

	ctx->nl_msg = nlmsg_alloc();
	if (!ctx->nl_msg) {
		msg(D_HANDSHAKE, "cannot allocate netlink message");
		goto err_sock;
	}

	ctx->nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!ctx->nl_cb) {
		msg(D_HANDSHAKE, "failed to allocate netlink callback");
		goto err_msg;
	}

	nl_socket_set_cb(ctx->nl_sock, ctx->nl_cb);

	genlmsg_put(ctx->nl_msg, 0, 0, ctx->ovpn_dco_id, 0, 0, cmd, 0);
	NLA_PUT_U32(ctx->nl_msg, OVPN_ATTR_IFINDEX, ovpn->ifindex);

	ctx->ovpn_dco_ifindex = ovpn->ifindex;

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
		msg(D_HANDSHAKE,
			"netlink received interrupt due to signal - ignoring");
		break;
	case -NLE_NOMEM:
		msg(D_HANDSHAKE, "netlink out of memory error");
		break;
	case -NLE_AGAIN:
		msg(D_HANDSHAKE,
			"netlink reports blocking read - aborting wait");
		break;
	default:
		if (ret)
			msg(D_HANDSHAKE, "netlink reports error (%d): %s",
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

	while (status == 1 && ovpn_nl_recvmsgs(ctx) > 0)
		;;

	if (status < 0)
		msg(D_HANDSHAKE, "failed to send netlink message: %s (%d)",
			strerror(-status), status);

	return status;
}

static int ovpn_nl_process_queue(struct nl_ctx *ctx, ovpn_nl_cb cb)
{
	int status = 1;

	nl_cb_err(ctx->nl_cb, NL_CB_CUSTOM, ovpn_nl_cb_error, &status);
	nl_cb_set(ctx->nl_cb, NL_CB_FINISH, NL_CB_CUSTOM, ovpn_nl_cb_finish,
		  &status);
	nl_cb_set(ctx->nl_cb, NL_CB_ACK, NL_CB_CUSTOM, ovpn_nl_cb_finish,
		  &status);

	if (cb)
		nl_cb_set(ctx->nl_cb, NL_CB_VALID, NL_CB_CUSTOM, cb, ctx);

	while (status == 1 && ovpn_nl_recvmsgs(ctx) > 0)
		;;

	if (status < 0)
		msg(D_HANDSHAKE, "failed to send netlink message: %s (%d)",
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
	NLA_PUT_U8(ctx->nl_msg, OVPN_ATTR_DATA_FORMAT, ovpn->data_format);

	if (ovpn->fragment_size != 0)
		NLA_PUT_U16(ctx->nl_msg, OVPN_ATTR_FRAGMENT_SIZE, ovpn->fragment_size);

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

int netlink_dco_set_peer(struct ovpn_ctx *ovpn)
{
	msg(D_HANDSHAKE, "set peer");

	struct nl_ctx *ctx;
	int ret = -1;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_SET_PEER);
	if (!ctx)
		return -ENOMEM;

	NLA_PUT_U32(ctx->nl_msg, OVPN_ATTR_KEEPALIVE_INTERVAL,
		    ovpn->keepalive_interval);
	NLA_PUT_U32(ctx->nl_msg, OVPN_ATTR_KEEPALIVE_TIMEOUT,
		    ovpn->keepalive_timeout);

	ret = ovpn_nl_msg_send(ctx, NULL);

	msg(D_HANDSHAKE, "set peer ok");
nla_put_failure:
	nl_ctx_free(ctx);
	return ret;
}

int netlink_dco_new_key(struct ovpn_ctx *ovpn, const uint32_t peer_id, const uint16_t key_id, enum ovpn_key_slot slot)
{
	msg(D_HANDSHAKE, "new key");
	struct nlattr *key_dir;
	struct nl_ctx *ctx = ovpn->nl_ctx;

	ctx->nl_msg = nlmsg_alloc();
	if (!ctx->nl_msg) {
		msg(D_HANDSHAKE, "cannot allocate netlink message");
	}

	genlmsg_put(ctx->nl_msg, 0, 0, ctx->ovpn_dco_id, 0, 0, OVPN_CMD_NEW_KEY, 0);
	NLA_PUT_U32(ctx->nl_msg, OVPN_ATTR_IFINDEX, ovpn->ifindex);

	NLA_PUT_U32(ctx->nl_msg, OVPN_ATTR_REMOTE_PEER_ID, peer_id);
	NLA_PUT_U8(ctx->nl_msg, OVPN_ATTR_KEY_SLOT, slot);
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

	if (slot == OVPN_KEY_SLOT_SECONDARY)
		ndm_time_get_monotonic(&ctx->key_install_time);
	else
		memset(&ctx->key_install_time, 0, sizeof(ctx->key_install_time));

nla_put_failure:
	//nl_ctx_free(ctx);
	nlmsg_free(ctx->nl_msg);

	return 0;
}

static int netlink_dco_swap_keys(struct nl_ctx *ctx)
{
	msg(D_HANDSHAKE, "swap keys");

	ctx->nl_msg = nlmsg_alloc();
	if (!ctx->nl_msg) {
		msg(D_HANDSHAKE, "cannot allocate netlink message");
	}

	genlmsg_put(ctx->nl_msg, 0, 0, ctx->ovpn_dco_id, 0, 0, OVPN_CMD_SWAP_KEYS, 0);
	NLA_PUT_U32(ctx->nl_msg, OVPN_ATTR_IFINDEX, ctx->ovpn_dco_ifindex);

	ovpn_nl_msg_send(ctx, NULL);
	msg(D_HANDSHAKE, "swap keys ok");

nla_put_failure:
	//nl_ctx_free(ctx);

	nlmsg_free(ctx->nl_msg);

	return 0;
}

static int netlink_dco_handle_packet(struct nl_msg *msg, void *arg)
{
	struct nl_ctx *ctx = (struct nl_ctx *)arg;
	struct context *c = ctx->c;
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *attrs[OVPN_ATTR_MAX + 1];
	const __u8 *data;
	size_t len;

	msg(D_HANDSHAKE, "received message");

	nla_parse(attrs, OVPN_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!attrs[OVPN_ATTR_PACKET]) {
		msg(D_HANDSHAKE, "no packet content in netlink message");
		return NL_SKIP;
	}

	len = nla_len(attrs[OVPN_ATTR_PACKET]);
	data = nla_data(attrs[OVPN_ATTR_PACKET]);

	if (memcmp(data, ping_string, PING_STRING_SIZE) == 0) {
		msg(D_HANDSHAKE, "got ping");

        /* reset packet received timer */
        if (c->options.ping_rec_timeout)
        {
            event_timeout_reset(&c->c2.ping_rec_interval);
        }

        /* reset packet send timer */
        if (c->options.ping_send_timeout)
        {
            event_timeout_reset(&c->c2.ping_send_interval);
        }

        /* increment authenticated receive byte count */
        c->c2.link_read_bytes_auth += c->c2.buf.len;
	}

	struct gc_arena gc = gc_new();

    msg(D_HANDSHAKE, "from dco: %s",
         format_hex(data, len, 80, &gc));

	gc_free(&gc);

	return NL_SKIP;
}

static int nl_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

void *netlink_dco_register(struct ovpn_ctx *ovpn, struct context *c)
{
	struct nl_ctx *ctx;
	int ret;

	ctx = nl_ctx_alloc(ovpn, OVPN_CMD_REGISTER_PACKET);
	if (!ctx)
		return NULL;

	nl_cb_set(ctx->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, nl_seq_check,
		  NULL);

	ctx->c = c;

	ret = ovpn_nl_msg_send(ctx, netlink_dco_handle_packet);
	if (ret < 0) {
		nl_ctx_free(ctx);
		return NULL;
	}

	ret = nl_socket_set_nonblocking(ctx->nl_sock);
	if (ret < 0) {
		nl_ctx_free(ctx);
		return NULL;
	}

	nl_socket_enable_msg_peek(ctx->nl_sock);

	nlmsg_free(ctx->nl_msg);

	return ctx;
}

void netlink_dco_cleanup_context(struct context *c)
{
	if (c->c2.nl_dco_ctx == NULL)
		return;

	nl_ctx_free((struct nl_ctx *)c->c2.nl_dco_ctx);
}

void netlink_dco_process(struct context *c)
{
	struct timespec ts;
	struct nl_ctx *ctx = (struct nl_ctx *)c->c2.nl_dco_ctx;

	if (ctx == NULL)
		return;

	msg(D_HANDSHAKE, "process nlqueue");

	ovpn_nl_process_queue(ctx, netlink_dco_handle_packet);

	if (!ndm_time_is_zero(&ctx->key_install_time)) {
		if (ndm_time_to_sec(&ts) >
			ndm_time_to_sec(&ctx->key_install_time) + KEYS_SWAP_INTERVAL_) {
			if (netlink_dco_swap_keys(ctx))
				msg(D_HANDSHAKE, "swap keys error");
			else
				memset(&ctx->key_install_time, 0, sizeof(ctx->key_install_time));
		}
	}

	msg(D_HANDSHAKE, "process nlqueue done");
}
