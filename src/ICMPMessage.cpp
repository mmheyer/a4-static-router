#include "ICMPMessage.h"
#include "utils.h"

// Public methods
void ICMPMessage::createEchoReply(uint32_t srcIp, uint32_t dstIp, const uint8_t* data, size_t dataSize) {
    sr_icmp_hdr_t icmpHdr = {0};
    icmpHdr.icmp_type = echo_reply;
    icmpHdr.icmp_code = 0;
    icmpHdr.icmp_sum = 0;

    std::vector<uint8_t> icmpPacket(sizeof(sr_icmp_hdr_t) + dataSize);
    std::memcpy(icmpPacket.data(), &icmpHdr, sizeof(sr_icmp_hdr_t));
    std::memcpy(icmpPacket.data() + sizeof(sr_icmp_hdr_t), data, dataSize);

    icmpHdr.icmp_sum = cksum(icmpPacket.data(), icmpPacket.size());
    std::memcpy(icmpPacket.data(), &icmpHdr, sizeof(sr_icmp_hdr_t));

    sendMessage(srcIp, dstIp, icmpPacket.data(), icmpPacket.size(), ip_protocol_icmp);
}

void ICMPMessage::createDestinationUnreachable(uint32_t srcIp, uint32_t dstIp, uint8_t code, const uint8_t* data, size_t dataSize) {
    sr_icmp_t3_hdr_t icmpHdr = {0};
    icmpHdr.icmp_type = destination_unreachable;
    icmpHdr.icmp_code = code;
    icmpHdr.icmp_sum = 0;

    std::memcpy(icmpHdr.data, data, std::min(dataSize, sizeof(icmpHdr.data)));

    icmpHdr.icmp_sum = cksum(reinterpret_cast<uint8_t*>(&icmpHdr), sizeof(icmpHdr));

    sendMessage(srcIp, dstIp, reinterpret_cast<uint8_t*>(&icmpHdr), sizeof(icmpHdr), ip_protocol_icmp);
}

void ICMPMessage::createTimeExceeded(uint32_t srcIp, uint32_t dstIp, const uint8_t* data, size_t dataSize) {
    sr_icmp_hdr_t icmpHdr = {0};
    icmpHdr.icmp_type = time_exceeded;
    icmpHdr.icmp_code = 0;
    icmpHdr.icmp_sum = 0;

    std::vector<uint8_t> icmpPacket(sizeof(sr_icmp_hdr_t) + dataSize);
    std::memcpy(icmpPacket.data(), &icmpHdr, sizeof(sr_icmp_hdr_t));
    std::memcpy(icmpPacket.data() + sizeof(sr_icmp_hdr_t), data, dataSize);

    icmpHdr.icmp_sum = cksum(icmpPacket.data(), icmpPacket.size());
    std::memcpy(icmpPacket.data(), &icmpHdr, sizeof(sr_icmp_hdr_t));

    sendMessage(srcIp, dstIp, icmpPacket.data(), icmpPacket.size(), ip_protocol_icmp);
}

void ICMPMessage::createPortUnreachable(uint32_t srcIp, uint32_t dstIp, const uint8_t* data, size_t dataSize) {
    createDestinationUnreachable(srcIp, dstIp, 3, data, dataSize);
}

// Private methods
void ICMPMessage::sendMessage(uint32_t srcIp, uint32_t dstIp, const uint8_t* payload, size_t payloadSize, uint8_t protocol) {
    std::vector<uint8_t> packet(sizeof(sr_ip_hdr_t) + payloadSize);
    wrapInIPHeader(packet, srcIp, dstIp, protocol);
    std::memcpy(packet.data() + sizeof(sr_ip_hdr_t), payload, payloadSize);

    // Create a Packet object, which is just a vector<uint8_t> here
    Packet finalPacket(packet.begin(), packet.end());
    packetSender.sendPacket(finalPacket, iface);
}

void ICMPMessage::wrapInIPHeader(std::vector<uint8_t>& packet, uint32_t srcIp, uint32_t dstIp, uint8_t protocol) {
    sr_ip_hdr_t* ipHdr = reinterpret_cast<sr_ip_hdr_t*>(packet.data());
    ipHdr->ip_v = 4; // IPv4
    ipHdr->ip_hl = sizeof(sr_ip_hdr_t) / 4; // Header length in 32-bit words
    ipHdr->ip_tos = 0; // Type of service
    ipHdr->ip_len = htons(packet.size()); // Total length
    ipHdr->ip_id = htons(0); // Identification
    ipHdr->ip_off = htons(0); // Fragment offset
    ipHdr->ip_ttl = 64; // Time to live
    ipHdr->ip_p = protocol; // Protocol
    ipHdr->ip_src = htonl(srcIp); // Source IP
    ipHdr->ip_dst = htonl(dstIp); // Destination IP
    ipHdr->ip_sum = 0; // Temporary value for checksum
    ipHdr->ip_sum = cksum(reinterpret_cast<uint8_t*>(ipHdr), sizeof(sr_ip_hdr_t));
}
