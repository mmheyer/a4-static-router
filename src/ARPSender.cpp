#include "ARPSender.h"
#include <iostream>
#include <iomanip>
#include <spdlog/spdlog.h>

ARPSender::ARPSender(std::shared_ptr<IPacketSender> packetSender)
    : packetSender_() {}

/**
 * @brief Sends an ARP request to resolve an IP address.
 * @param targetIP The IP address to resolve.
 * @param senderIP The IP address of the sender.
 * @param senderMac The MAC address of the sender.
 * @param iface The interface to send the ARP request on.
 */
void ARPSender::sendArpRequest(uint32_t targetIP, uint32_t senderIP, const uint8_t senderMac[6], const std::string& iface) {
    spdlog::info("Sending ARP request for IP {} from sender IP {} on interface {}", targetIP, senderIP, iface);

    // Build an ARP request packet
    std::vector<uint8_t> packet(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

    // Ethernet header
    auto* ethHeader = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    std::fill(std::begin(ethHeader->ether_dhost), std::end(ethHeader->ether_dhost), 0xFF); // Broadcast MAC address
    std::memcpy(ethHeader->ether_shost, senderMac, ETHER_ADDR_LEN); // Sender's MAC address
    ethHeader->ether_type = htons(ethertype_arp);

    // ARP header
    auto* arpHeader = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    arpHeader->ar_hrd = htons(arp_hrd_ethernet); // Hardware type: Ethernet
    arpHeader->ar_pro = htons(ethertype_ip);     // Protocol type: IPv4
    arpHeader->ar_hln = ETHER_ADDR_LEN;         // Hardware address length
    arpHeader->ar_pln = sizeof(uint32_t);       // Protocol address length
    arpHeader->ar_op = htons(arp_op_request);   // ARP operation: request

    // Sender's hardware and protocol addresses
    std::memcpy(arpHeader->ar_sha, senderMac, ETHER_ADDR_LEN);
    arpHeader->ar_sip = htonl(senderIP);

    // Target's hardware address is empty for a request
    std::fill(std::begin(arpHeader->ar_tha), std::end(arpHeader->ar_tha), 0x00);
    arpHeader->ar_tip = htonl(targetIP);

    // Log packet contents
    spdlog::debug("ARP Request: Sender IP: {}, Target IP: {}", senderIP, targetIP);

    // Send the ARP request
    packetSender_->sendPacket(packet, iface);
}

void ARPSender::sendArpReply(uint32_t targetIP,
                             const uint8_t targetMac[6],
                             uint32_t senderIP,
                             const uint8_t senderMac[6],
                             const std::string& iface) {
    // Create ARP reply packet
    std::vector<uint8_t> packet(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    auto* ethHeader = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    auto* arpHeader = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));

    // Populate Ethernet header
    memcpy(ethHeader->ether_dhost, targetMac, 6); // Target MAC address
    memcpy(ethHeader->ether_shost, senderMac, 6); // Sender MAC address
    ethHeader->ether_type = htons(ethertype_arp);

    // Populate ARP header
    arpHeader->ar_hrd = htons(arp_hrd_ethernet);
    arpHeader->ar_pro = htons(ethertype_ip);
    arpHeader->ar_hln = 6;
    arpHeader->ar_pln = 4;
    arpHeader->ar_op = htons(arp_op_reply);
    memcpy(arpHeader->ar_sha, senderMac, 6); // Sender MAC address
    arpHeader->ar_sip = htonl(senderIP); // Sender IP address
    memcpy(arpHeader->ar_tha, targetMac, 6); // Target MAC address
    arpHeader->ar_tip = htonl(targetIP); // Target IP address

    // Send the packet
    packetSender_->sendPacket(packet, iface);
}