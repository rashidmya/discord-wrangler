#include "nfq_loop.hpp"
#include "log.hpp"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <string.h>
#include <unistd.h>
#include <atomic>
#include <vector>

namespace wrangler::nfq {

namespace {
mnl_socket*           s_nl   = nullptr;
uint16_t              s_queue_num = 0;
Handler               s_handler;
std::atomic<bool>     s_running{false};

uint32_t              s_portid = 0;

int parse_attr_cb(const nlattr* attr, void* data) {
    const nlattr** tb = static_cast<const nlattr**>(data);
    int type = mnl_attr_get_type(attr);
    if (mnl_attr_type_valid(attr, NFQA_MAX) < 0) return MNL_CB_OK;
    tb[type] = attr;
    return MNL_CB_OK;
}

int queue_cb(const nlmsghdr* nlh, void* /*data*/) {
    const nlattr* attr[NFQA_MAX + 1] = {};
    if (mnl_attr_parse(nlh, sizeof(nfgenmsg), parse_attr_cb, attr) < 0) {
        WLOG_WARN("mnl_attr_parse failed");
        return MNL_CB_OK;
    }
    if (!attr[NFQA_PACKET_HDR]) {
        WLOG_WARN("packet without NFQA_PACKET_HDR");
        return MNL_CB_OK;
    }
    auto* ph = static_cast<nfqnl_msg_packet_hdr*>(mnl_attr_get_payload(attr[NFQA_PACKET_HDR]));
    uint32_t packet_id = ntohl(ph->packet_id);

    // Default response if anything goes wrong is to accept the packet,
    // so we capture this here and only override if we successfully dispatch.
    auto send_verdict = [packet_id](uint32_t verdict) {
        char buf[MNL_SOCKET_BUFFER_SIZE];
        nlmsghdr* h = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, s_queue_num);
        nfq_nlmsg_verdict_put(h, packet_id, verdict);
        if (mnl_socket_sendto(s_nl, h, h->nlmsg_len) < 0) {
            WLOG_WARN("send verdict: %s", strerror(errno));
        }
    };

    if (!attr[NFQA_PAYLOAD]) {
        WLOG_WARN("packet without payload");
        send_verdict(NF_ACCEPT);
        return MNL_CB_OK;
    }

    auto* payload = static_cast<uint8_t*>(mnl_attr_get_payload(attr[NFQA_PAYLOAD]));
    int plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    if (plen < static_cast<int>(sizeof(iphdr) + sizeof(udphdr))) {
        WLOG_WARN("packet too short: %d", plen);
        send_verdict(NF_ACCEPT);
        return MNL_CB_OK;
    }

    const auto* ip = reinterpret_cast<const iphdr*>(payload);
    if (ip->version != 4 || ip->protocol != IPPROTO_UDP) {
        send_verdict(NF_ACCEPT);
        return MNL_CB_OK;
    }
    size_t ip_hl = ip->ihl * 4u;
    if (ip_hl + sizeof(udphdr) > static_cast<size_t>(plen)) {
        WLOG_WARN("ip header truncated");
        send_verdict(NF_ACCEPT);
        return MNL_CB_OK;
    }
    const auto* udp = reinterpret_cast<const udphdr*>(payload + ip_hl);
    uint16_t udp_total = ntohs(udp->len);
    if (udp_total < sizeof(udphdr)) {
        send_verdict(NF_ACCEPT);
        return MNL_CB_OK;
    }
    uint16_t payload_len = static_cast<uint16_t>(udp_total - sizeof(udphdr));

    PacketEvent ev{
        ip->saddr,
        udp->source,
        ip->daddr,
        udp->dest,
        payload_len,
        packet_id,
        [send_verdict] { send_verdict(NF_ACCEPT); },
    };

    if (s_handler) {
        s_handler(std::move(ev));
    } else {
        send_verdict(NF_ACCEPT);
    }
    return MNL_CB_OK;
}

} // namespace

int init(uint16_t queue_num, Handler handler) {
    s_queue_num = queue_num;
    s_handler   = std::move(handler);

    s_nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!s_nl) { int e = errno; WLOG_ERROR("mnl_socket_open: %s", strerror(e)); return -e; }
    if (mnl_socket_bind(s_nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        int e = errno; WLOG_ERROR("mnl_socket_bind: %s", strerror(e));
        return -e;
    }
    s_portid = mnl_socket_get_portid(s_nl);

    char buf[MNL_SOCKET_BUFFER_SIZE];
    nlmsghdr* h = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_cmd(h, AF_INET, NFQNL_CFG_CMD_BIND);
    if (mnl_socket_sendto(s_nl, h, h->nlmsg_len) < 0) {
        int e = errno; WLOG_ERROR("CFG_CMD_BIND: %s", strerror(e));
        return -e;
    }

    h = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_params(h, NFQNL_COPY_PACKET, 0xffff);
    mnl_attr_put_u32(h, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(h, NFQA_CFG_MASK,  htonl(NFQA_CFG_F_GSO));
    if (mnl_socket_sendto(s_nl, h, h->nlmsg_len) < 0) {
        int e = errno; WLOG_ERROR("CFG_PARAMS: %s", strerror(e));
        return -e;
    }

    WLOG_INFO("nfqueue %u attached", queue_num);
    return 0;
}

int run() {
    s_running.store(true);
    std::vector<char> buf(MNL_SOCKET_BUFFER_SIZE);
    while (s_running.load()) {
        ssize_t n = mnl_socket_recvfrom(s_nl, buf.data(), buf.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOBUFS) {
                WLOG_WARN("nfqueue ENOBUFS (kernel queue overrun) — continuing");
                continue;
            }
            WLOG_ERROR("mnl_socket_recvfrom: %s", strerror(errno));
            return -errno;
        }
        int r = mnl_cb_run(buf.data(), n, 0, s_portid, queue_cb, nullptr);
        if (r < 0) {
            WLOG_ERROR("mnl_cb_run: %s", strerror(errno));
            return -errno;
        }
    }
    WLOG_INFO("nfqueue loop exiting");
    return 0;
}

void shutdown() {
    s_running.store(false);
    // Closing the socket from another thread is the standard way to wake mnl_socket_recvfrom.
    if (s_nl) {
        mnl_socket_close(s_nl);
        s_nl = nullptr;
    }
}

} // namespace wrangler::nfq
