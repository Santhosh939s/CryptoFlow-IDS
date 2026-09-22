#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define MAX_PAYLOAD_CAPTURE 1024
#define MIN_PAYLOAD_FILTER  200

// Event structure pushed to Python user-space via BPF_PERF_OUTPUT
struct packet_event_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u32 packet_size;
    u32 payload_len;
    u8  protocol;                // IPPROTO_TCP (6) or IPPROTO_UDP (17)
    u8  is_quic;                 // 1 if identified as QUIC, 0 otherwise
    u16 payload_captured_len;
    unsigned char payload[MAX_PAYLOAD_CAPTURE];
};

BPF_PERF_OUTPUT(events);

/**
 * Socket filter program attached to raw network socket.
 * Inspects packet in kernel space, extracts metadata, checks QUIC markers,
 * copies a payload slice, and emits it to user-space via perf ring buffer.
 */
int packet_filter(struct __sk_buff *skb) {
    u8 *cursor = 0;

    // 1. Parse Ethernet Header
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (ethernet->type != 0x0800) { // ETH_P_IP (IPv4 only)
        return 0;
    }

    // 2. Parse IPv4 Header
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    u32 ip_header_len = ip->hlen << 2;
    u32 ip_total_len = ip->tlen;

    struct packet_event_t evt = {};
    evt.src_ip = ip->src;
    evt.dst_ip = ip->dst;
    evt.packet_size = skb->len;
    evt.protocol = ip->nextp;
    evt.is_quic = 0;

    u32 l4_header_len = 0;
    u32 payload_offset = 0;

    // 3. Parse L4 Transport Layer (TCP or UDP)
    if (ip->nextp == IPPROTO_TCP) {
        struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
        evt.src_port = tcp->src_port;
        evt.dst_port = tcp->dst_port;

        l4_header_len = tcp->offset << 2;
        payload_offset = sizeof(struct ethernet_t) + ip_header_len + l4_header_len;

        // In-kernel calculation of TCP payload length
        if (ip_total_len > (ip_header_len + l4_header_len)) {
            evt.payload_len = ip_total_len - (ip_header_len + l4_header_len);
        } else {
            evt.payload_len = 0;
        }

    } else if (ip->nextp == IPPROTO_UDP) {
        struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
        evt.src_port = udp->sport;
        evt.dst_port = udp->dport;

        l4_header_len = sizeof(struct udp_t);
        payload_offset = sizeof(struct ethernet_t) + ip_header_len + l4_header_len;

        // In-kernel calculation of UDP payload length
        if (udp->length > sizeof(struct udp_t)) {
            evt.payload_len = udp->length - sizeof(struct udp_t);
        } else {
            evt.payload_len = 0;
        }

        // 4. QUIC Detection Logic (RFC 9000)
        // QUIC runs over UDP (standard port 443 or alternative 8443)
        if (evt.dst_port == 443 || evt.src_port == 443 || evt.dst_port == 8443) {
            u8 first_byte = 0;
            if (evt.payload_len > 0) {
                bpf_skb_load_bytes(skb, payload_offset, &first_byte, 1);
                // QUIC fixed bit is always 1 (0x40) in both Long Header (0x80 | 0x40)
                // and Short Header (0x40) packets
                if ((first_byte & 0x40) != 0) {
                    evt.is_quic = 1;
                }
            }
        }
    } else {
        return 0; // Ignore ICMP, IGMP, etc.
    }

    // Filter packets with payloads below the minimum analysis threshold
    if (evt.payload_len < MIN_PAYLOAD_FILTER) {
        return 0;
    }

    // 5. Copy payload sample safely for user-space entropy calculation
    u32 capture_len = evt.payload_len;
    if (capture_len > MAX_PAYLOAD_CAPTURE) {
        capture_len = MAX_PAYLOAD_CAPTURE;
    }
    evt.payload_captured_len = (u16)capture_len;

    bpf_skb_load_bytes(skb, payload_offset, evt.payload, capture_len);

    // Push event to user space via BPF ring buffer
    events.perf_submit(skb, &evt, sizeof(evt));

    // Return 0 so packet isn't duplicated into the user-space raw socket buffer
    return 0;
}
