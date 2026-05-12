#include "direct/nfq_loop.hpp"
#include "log.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <unistd.h>
#include <vector>

namespace wrangler::direct {

namespace {

int parse_attr_cb(const nlattr* attr, void* data) {
    const nlattr** tb = static_cast<const nlattr**>(data);
    int type = mnl_attr_get_type(attr);
    if (mnl_attr_type_valid(attr, NFQA_MAX) < 0) return MNL_CB_OK;
    tb[type] = attr;
    return MNL_CB_OK;
}

} // namespace

NfqLoop::~NfqLoop() {
    shutdown();
    if (nl_) { mnl_socket_close(nl_); nl_ = nullptr; }
}

void NfqLoop::send_verdict(uint32_t packet_id, uint32_t verdict) {
    char buf[MNL_SOCKET_BUFFER_SIZE];
    nlmsghdr* h = nfq_nlmsg_put(buf, NFQNL_MSG_VERDICT, queue_num_);
    nfq_nlmsg_verdict_put(h, packet_id, verdict);
    if (mnl_socket_sendto(nl_, h, h->nlmsg_len) < 0) {
        WLOG_WARN("send verdict: %s", std::strerror(errno));
    }
}

int NfqLoop::dispatch(const nlmsghdr* nlh) {
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
    const uint32_t packet_id = ntohl(ph->packet_id);

    if (!attr[NFQA_PAYLOAD]) {
        WLOG_WARN("packet without payload");
        send_verdict(packet_id, NF_ACCEPT);
        return MNL_CB_OK;
    }

    auto* payload = static_cast<uint8_t*>(mnl_attr_get_payload(attr[NFQA_PAYLOAD]));
    int plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
    if (plen < static_cast<int>(sizeof(iphdr) + sizeof(udphdr))) {
        WLOG_WARN("packet too short: %d", plen);
        send_verdict(packet_id, NF_ACCEPT);
        return MNL_CB_OK;
    }

    const auto* ip = reinterpret_cast<const iphdr*>(payload);
    if (ip->version != 4 || ip->protocol != IPPROTO_UDP) {
        send_verdict(packet_id, NF_ACCEPT);
        return MNL_CB_OK;
    }
    const size_t ip_hl = ip->ihl * 4u;
    if (ip_hl + sizeof(udphdr) > static_cast<size_t>(plen)) {
        WLOG_WARN("ip header truncated");
        send_verdict(packet_id, NF_ACCEPT);
        return MNL_CB_OK;
    }
    const auto* udp = reinterpret_cast<const udphdr*>(payload + ip_hl);
    const uint16_t udp_total = ntohs(udp->len);
    if (udp_total < sizeof(udphdr)) {
        send_verdict(packet_id, NF_ACCEPT);
        return MNL_CB_OK;
    }
    const uint16_t payload_len = static_cast<uint16_t>(udp_total - sizeof(udphdr));

    PacketEvent ev{
        ip->saddr,
        udp->source,
        ip->daddr,
        udp->dest,
        payload_len,
        packet_id,
        [this, packet_id] { send_verdict(packet_id, NF_ACCEPT); },
    };

    if (handler_) {
        handler_(std::move(ev));
    } else {
        send_verdict(packet_id, NF_ACCEPT);
    }
    return MNL_CB_OK;
}

int NfqLoop::init(uint16_t queue_num, Handler handler) {
    queue_num_ = queue_num;
    handler_   = std::move(handler);

    int wp[2];
    if (::pipe2(wp, O_CLOEXEC | O_NONBLOCK) < 0) {
        int e = errno;
        WLOG_ERROR("nfq: self-pipe pipe2: %s", std::strerror(e));
        return -e;
    }
    wake_rfd_ = wp[0];
    wake_wfd_ = wp[1];

    nl_ = mnl_socket_open(NETLINK_NETFILTER);
    if (!nl_) {
        int e = errno;
        WLOG_ERROR("mnl_socket_open: %s", std::strerror(e));
        return -e;
    }
    if (mnl_socket_bind(nl_, 0, MNL_SOCKET_AUTOPID) < 0) {
        int e = errno;
        WLOG_ERROR("mnl_socket_bind: %s", std::strerror(e));
        return -e;
    }
    portid_ = mnl_socket_get_portid(nl_);

    char buf[MNL_SOCKET_BUFFER_SIZE];
    nlmsghdr* h = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_cmd(h, AF_INET, NFQNL_CFG_CMD_BIND);
    if (mnl_socket_sendto(nl_, h, h->nlmsg_len) < 0) {
        int e = errno;
        WLOG_ERROR("CFG_CMD_BIND: %s", std::strerror(e));
        return -e;
    }

    h = nfq_nlmsg_put(buf, NFQNL_MSG_CONFIG, queue_num);
    nfq_nlmsg_cfg_put_params(h, NFQNL_COPY_PACKET, 0xffff);
    mnl_attr_put_u32(h, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
    mnl_attr_put_u32(h, NFQA_CFG_MASK,  htonl(NFQA_CFG_F_GSO));
    if (mnl_socket_sendto(nl_, h, h->nlmsg_len) < 0) {
        int e = errno;
        WLOG_ERROR("CFG_PARAMS: %s", std::strerror(e));
        return -e;
    }

    WLOG_INFO("nfqueue %u attached", queue_num);
    return 0;
}

int NfqLoop::run() {
    if (!nl_) return -EBADF;

    // Dispatch trampoline: libmnl callbacks take a `void* data`, but we want
    // a non-static member call. The user-data carries `this`.
    auto cb = [](const nlmsghdr* nlh, void* data) -> int {
        return static_cast<NfqLoop*>(data)->dispatch(nlh);
    };

    std::vector<char> buf(MNL_SOCKET_BUFFER_SIZE);
    pollfd pfds[2];
    pfds[0].fd = mnl_socket_get_fd(nl_);
    pfds[0].events = POLLIN;
    pfds[1].fd = wake_rfd_;
    pfds[1].events = POLLIN;

    while (true) {
        pfds[0].revents = 0;
        pfds[1].revents = 0;
        int pr = ::poll(pfds, 2, -1);
        if (pr < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            WLOG_ERROR("nfq poll: %s", std::strerror(e));
            return -e;
        }
        if (pfds[1].revents & POLLIN) {
            WLOG_INFO("nfqueue loop exiting");
            return 0;
        }
        if (!(pfds[0].revents & POLLIN)) continue;

        ssize_t n = mnl_socket_recvfrom(nl_, buf.data(), buf.size());
        if (n < 0) {
            int e = errno;
            if (e == EINTR) continue;
            if (e == ENOBUFS) {
                WLOG_WARN("nfqueue ENOBUFS (kernel queue overrun) -- continuing");
                continue;
            }
            WLOG_ERROR("mnl_socket_recvfrom: %s", std::strerror(e));
            return -e;
        }
        int r = mnl_cb_run(buf.data(), n, 0, portid_, cb, this);
        if (r < 0) {
            int e = errno;
            WLOG_ERROR("mnl_cb_run: %s", std::strerror(e));
            return -e;
        }
    }
}

void NfqLoop::shutdown() noexcept {
    // Async-signal-safe path: just write one byte to the self-pipe. The loop
    // notices the wake fd is readable and returns. We deliberately do NOT
    // touch nl_/mnl_socket_close here — those are not safe from a signal
    // handler.
    if (wake_wfd_ >= 0) {
        const char b = 'x';
        ssize_t n;
        do { n = ::write(wake_wfd_, &b, 1); } while (n < 0 && errno == EINTR);
    }
}

} // namespace wrangler::direct
