#include "ICMPSender.h"
#include "utils.h"
#include <cstring>
#include <arpa/inet.h>
#include <iostream>
#include <spdlog/spdlog.h>

ICMPSender::ICMPSender(std::shared_ptr<IPacketSender> packetSender)
    : packetSender_(std::move(packetSender)) {}

// void ICMPSender::sendEchoReply(const std::vector<uint8_t>& requestPacket,
//                                const mac_addr& sourceMAC,
//                                uint32_t sourceIP,
//                                const std::string& iface) {
//     uint32_t destIP = extractSourceIP(requestPacket);
//     mac_addr destMAC = extractSourceMAC(requestPacket);

//     auto icmpPacket = constructICMPPacket(requestPacket, sourceIP, destIP, sourceMAC, destMAC, 0, 0);
//     packetSender_->sendPacket(icmpPacket, iface);
// }

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

void ICMPSender::sendDestinationUnreachable(const std::vector<uint8_t>& originalPacket,
                                            const mac_addr& sourceMAC,
                                            uint32_t sourceIP,
                                            const mac_addr& destMAC,
                                            uint32_t destIP,
                                            const std::string& iface,
                                            uint8_t icmpCode) {
    spdlog::info("Sending ICMP Destination Unreachable (Code: {}).", icmpCode);

    // Construct ICMP Destination Unreachable packet
    auto icmpPacket = constructICMPPacket(originalPacket, sourceIP, destIP, sourceMAC, destMAC, 3, icmpCode);

    // Log constructed ICMP packet details (if needed for debugging)
    spdlog::debug("Constructed ICMP Destination Unreachable packet. Sending on interface {}.", iface);

    // Send the packet
    packetSender_->sendPacket(icmpPacket, iface);
}

void ICMPSender::sendPortUnreachable(const std::vector<uint8_t>& originalPacket,
                                     const mac_addr& sourceMAC,
                                     uint32_t sourceIP,
                                     const mac_addr& destMAC,
                                     uint32_t destIP,
                                     const std::string& iface) {
    spdlog::info("Sending ICMP Port Unreachable message.");

    spdlog::info("Source MAC for ICMP port unreachable: {}", macToString(sourceMAC));
    spdlog::info("Source IP for ICMP port unreachable:");
    print_addr_ip_int(ntohl(sourceIP));
    spdlog::info("Destination MAC for ICMP port unreachable: {}", macToString(destMAC));
    spdlog::info("Destination IP for ICMP port unreachable:");
    print_addr_ip_int(destIP);

    auto icmpPacket = constructICMPPacket(originalPacket, sourceIP, destIP, sourceMAC, destMAC, 3, 3);
    spdlog::debug("Successfully constructed ICMP packet.");
    packetSender_->sendPacket(icmpPacket, iface);

    spdlog::info("ICMP Port Unreachable sent to interface: {}", iface);
}
