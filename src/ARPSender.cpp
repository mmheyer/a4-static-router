#include <cstring>

#include "ARPSender.h"

ARPSender::ARPSender(std::shared_ptr<IPacketSender> packetSender)
    : packetSender_() {}

void ARPSender::sendArpRequest(uint32_t targetIP,
                               uint32_t senderIP,
                               const uint8_t senderMac[6],
                               const std::string& iface) {
    // Create ARP request packet
    std::vector<uint8_t> packet(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    auto* ethHeader = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    auto* arpHeader = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));

    // Populate Ethernet header
    memset(ethHeader->ether_dhost, 0xFF, 6); // Broadcast MAC address
    memcpy(ethHeader->ether_shost, senderMac, 6); // Sender MAC
    ethHeader->ether_type = htons(ethertype_arp);

    // Populate ARP header
    arpHeader->ar_hrd = htons(arp_hrd_ethernet);
    arpHeader->ar_pro = htons(ethertype_ip);
    arpHeader->ar_hln = 6;
    arpHeader->ar_pln = 4;
    arpHeader->ar_op = htons(arp_op_request);
    memcpy(arpHeader->ar_sha, senderMac, 6); // Sender MAC address
    arpHeader->ar_sip = htonl(senderIP); // Sender IP address
    memset(arpHeader->ar_tha, 0, 6); // Target MAC address (unknown)
    arpHeader->ar_tip = htonl(targetIP); // Target IP address

    // Send the packet
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
