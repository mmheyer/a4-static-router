#include "ICMPSender.h"
#include "utils.h"
#include <cstring>
#include <arpa/inet.h>
#include <iostream>
ICMPSender::ICMPSender(std::shared_ptr<IPacketSender> packetSender)
    : packetSender_(std::move(packetSender)) {}

void ICMPSender::sendEchoReply(const std::vector<uint8_t>& requestPacket,
                               const mac_addr& sourceMAC,
                               uint32_t sourceIP,
                               const std::string& iface) {
    uint32_t destIP = extractSourceIP(requestPacket);
    mac_addr destMAC = extractSourceMAC(requestPacket);

    auto icmpPacket = constructICMPPacket(requestPacket, sourceIP, destIP, sourceMAC, destMAC, 0, 0);
    packetSender_->sendPacket(icmpPacket, iface);
}

void ICMPSender::sendDestinationUnreachable(const std::vector<uint8_t>& originalPacket,
                                            const mac_addr& sourceMAC,
                                            uint32_t sourceIP,
                                            const mac_addr& destMAC,
                                            uint32_t destIP,
                                            const std::string& iface,
                                            DestinationUnreachableCode code) {
    auto icmpPacket = constructICMPPacket(originalPacket, sourceIP, destIP, sourceMAC, destMAC, 3, static_cast<uint8_t>(code));
    packetSender_->sendPacket(icmpPacket, iface);
}

void ICMPSender::sendTimeExceeded(const std::vector<uint8_t>& originalPacket,
                                  const mac_addr& sourceMAC,
                                  uint32_t sourceIP,
                                  const mac_addr& destMAC,
                                  uint32_t destIP,
                                  const std::string& iface) {
    std::cout << "TIME EXCEEDED" << std::endl;
    auto icmpPacket = constructICMPPacket(originalPacket, sourceIP, destIP, sourceMAC, destMAC, 11, 0);
    std::cout << "time exceeded pkt sent " << std::endl;
    packetSender_->sendPacket(icmpPacket, iface);
}

std::vector<uint8_t> ICMPSender::constructICMPPacket(const std::vector<uint8_t>& originalPacket,
                                                     uint32_t sourceIP,
                                                     uint32_t destIP,
                                                     const mac_addr& sourceMAC,
                                                     const mac_addr& destMAC,
                                                     uint8_t icmpType,
                                                     uint8_t icmpCode) {
    std::vector<uint8_t> packet(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));

    // Ethernet header
    auto* ethHeader = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    memcpy(ethHeader->ether_shost, sourceMAC.data(), ETHER_ADDR_LEN);
    memcpy(ethHeader->ether_dhost, destMAC.data(), ETHER_ADDR_LEN);
    ethHeader->ether_type = htons(ethertype_ip);

    // IP header
    auto* ipHeader = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    ipHeader->ip_v = 4;
    ipHeader->ip_hl = 5;
    ipHeader->ip_tos = 0;
    ipHeader->ip_len = htons(packet.size() - sizeof(sr_ethernet_hdr_t));
    ipHeader->ip_id = 0;
    ipHeader->ip_off = 0;
    ipHeader->ip_ttl = 64;
    ipHeader->ip_p = ip_protocol_icmp;
    ipHeader->ip_src = htonl(sourceIP);
    ipHeader->ip_dst = htonl(destIP);
    ipHeader->ip_sum = 0;
    ipHeader->ip_sum = cksum(ipHeader, sizeof(sr_ip_hdr_t));

    // ICMP header
    auto* icmpHeader = reinterpret_cast<sr_icmp_t3_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmpHeader->icmp_type = icmpType;
    icmpHeader->icmp_code = icmpCode;
    icmpHeader->unused = 0;
    icmpHeader->next_mtu = 0;
    memcpy(icmpHeader->data, originalPacket.data(), std::min(ICMP_DATA_SIZE, static_cast<int>(originalPacket.size())));
    icmpHeader->icmp_sum = 0;
    icmpHeader->icmp_sum = cksum(icmpHeader, sizeof(sr_icmp_t3_hdr_t));

    return packet;
}