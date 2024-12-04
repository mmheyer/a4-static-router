#include "ICMPSender.h"
#include <cstring>
#include "utils.h"
#include "protocol.h"
#include <spdlog/spdlog.h>

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
    ipHeader->ip_sum = cksum(ipHeader, sizeof(sr_ip_hdr_t));

    // Populate ICMP header
    icmpHeader->icmp_type = icmpType;
    icmpHeader->icmp_code = icmpCode;
    icmpHeader->icmp_sum = cksum(icmpHeader, sizeof(sr_icmp_t3_hdr_t));
    memcpy(icmpHeader->data, originalPacket.data(), std::min(ICMP_DATA_SIZE, static_cast<int>(originalPacket.size())));

    // Calculate checksum (not implemented here)
    return message;
}

void ICMPSender::sendICMPEchoReply(const std::vector<uint8_t>& requestPacket, const std::string& iface, uint32_t sourceIP) {
    // Ensure the packet contains enough data for Ethernet, IP, and ICMP headers
    if (requestPacket.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
        spdlog::error("Request packet is too small to construct an ICMP Echo Reply.");
        return;
    }

    // Extract headers from the request packet
    const auto* ethHeader = reinterpret_cast<const sr_ethernet_hdr_t*>(requestPacket.data());
    const auto* ipHeader = reinterpret_cast<const sr_ip_hdr_t*>(requestPacket.data() + sizeof(sr_ethernet_hdr_t));
    const auto* icmpHeader = reinterpret_cast<const sr_icmp_hdr_t*>(requestPacket.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    // Verify that the request is an ICMP Echo Request (type 8)
    if (icmpHeader->icmp_type != 8 /* Echo Request */) {
        spdlog::error("ICMP packet is not an Echo Request. Dropping packet.");
        return;
    }

    // Prepare source and destination IP addresses for the reply
    uint32_t destIP = ntohl(ipHeader->ip_src); // Destination is the original source IP
    uint32_t replySourceIP = sourceIP; // Router's source IP

    // Construct the ICMP Echo Reply packet
    std::vector<uint8_t> icmpReplyPacket = constructICMPMessage(requestPacket, replySourceIP, destIP, 0 /* ICMP Type: Echo Reply */, 0 /* ICMP Code */);

    // Update the Ethernet header
    auto* replyEthHeader = reinterpret_cast<sr_ethernet_hdr_t*>(icmpReplyPacket.data());
    memcpy(replyEthHeader->ether_dhost, ethHeader->ether_shost, ETHER_ADDR_LEN); // Target MAC is the requester's MAC
    memcpy(replyEthHeader->ether_shost, ethHeader->ether_dhost, ETHER_ADDR_LEN); // Source MAC is the router's MAC
    replyEthHeader->ether_type = htons(ethertype_ip);

    // Send the packet
    packetSender_->sendPacket(icmpReplyPacket, iface);
    spdlog::info("ICMP Echo Reply sent to IP: {:#08x}", destIP);
}
