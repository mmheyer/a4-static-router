#include "ICMPSender.h"

ICMPSender::ICMPSender(std::shared_ptr<IPacketSender> packetSender)
    : packetSender_() {}

void ICMPSender::sendDestinationUnreachable(const std::vector<uint8_t>& packet,
                                            const std::string& iface,
                                            uint32_t sourceIP,
                                            uint8_t icmpCode) {
    uint32_t destIP = *reinterpret_cast<const uint32_t*>(&packet[12]); // Source IP from the original packet
    std::vector<uint8_t> icmpMessage = constructICMPMessage(packet, sourceIP, destIP, 3 /* ICMP Type */, icmpCode);
    packetSender_->sendPacket(icmpMessage, iface);
}

void ICMPSender::sendTimeExceeded(const std::vector<uint8_t>& packet,
                                  const std::string& iface,
                                  uint32_t sourceIP) {
    uint32_t destIP = *reinterpret_cast<const uint32_t*>(&packet[12]); // Source IP from the original packet
    std::vector<uint8_t> icmpMessage = constructICMPMessage(packet, sourceIP, destIP, 11 /* ICMP Type */, 0);
    packetSender_->sendPacket(icmpMessage, iface);
}

std::vector<uint8_t> ICMPSender::constructICMPMessage(const std::vector<uint8_t>& originalPacket,
                                                      uint32_t sourceIP,
                                                      uint32_t destIP,
                                                      uint8_t icmpType,
                                                      uint8_t icmpCode) {
    std::vector<uint8_t> message(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    auto* ipHeader = reinterpret_cast<sr_ip_hdr_t*>(message.data());
    auto* icmpHeader = reinterpret_cast<sr_icmp_t3_hdr_t*>(message.data() + sizeof(sr_ip_hdr_t));

    // Populate IP header
    ipHeader->ip_v = 4;
    ipHeader->ip_hl = 5;
    ipHeader->ip_tos = 0;
    ipHeader->ip_len = htons(message.size());
    ipHeader->ip_id = 0;
    ipHeader->ip_off = 0;
    ipHeader->ip_ttl = 64;
    ipHeader->ip_p = ip_protocol_icmp;
    ipHeader->ip_src = htonl(sourceIP);
    ipHeader->ip_dst = htonl(destIP);
    ipHeader->ip_sum = 0; // Assume checksum calculation done elsewhere

    // Populate ICMP header
    icmpHeader->icmp_type = icmpType;
    icmpHeader->icmp_code = icmpCode;
    icmpHeader->icmp_sum = 0; // Assume checksum calculation done elsewhere
    memcpy(icmpHeader->data, originalPacket.data(), std::min(ICMP_DATA_SIZE, static_cast<int>(originalPacket.size())));

    // Calculate checksum (not implemented here)
    return message;
}
