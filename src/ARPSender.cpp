#include "ARPSender.h"
#include <iostream>
#include <iomanip>
ARPSender::ARPSender(std::shared_ptr<IPacketSender> packetSender)
    : packetSender_() {}

void ARPSender::sendArpRequest(uint32_t targetIP,
                               uint32_t senderIP,
                               const uint8_t senderMac[6],
                               const std::string& iface) {
    std::cout << "ARP SENDER ||  in send arp request" << std::endl;

    // Check if senderMac is a valid pointer (not nullptr) and size is correct
    if (senderMac == nullptr) {
        std::cout << "Error: senderMac is null!" << std::endl;
        return; // Avoid proceeding further if senderMac is invalid
    }

    // Create ARP request packet
    std::vector<uint8_t> reply(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    if (reply.empty()) {
        std::cout << "Error: Failed to allocate memory for reply!" << std::endl;
        return; // Ensure memory allocation is successful
    }
    if (reply.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
        std::cout << "Error: Allocated packet size is smaller than expected!" << std::endl;
        return;
    }
    auto *replyEthH = reinterpret_cast<sr_ethernet_hdr_t *>(reply.data());
    auto *replyArpH = reinterpret_cast<sr_arp_hdr_t *>(reply.data() + sizeof(sr_ethernet_hdr_t));

    std::cout << "ARP SENDER || Created packet of size: " << reply.size() << " bytes" << std::endl;

    // Populate Ethernet header
    memset(replyEthH->ether_dhost, 0xFF, 6); // Broadcast MAC address
    memcpy(replyEthH->ether_shost, senderMac, 6); // Sender MAC
    replyEthH->ether_type = htons(ethertype_arp);

    std::cout << "ARP SENDER ||  Ethernet Header:" << std::endl;
    std::cout << "ARP SENDER ||  Destination MAC: FF:FF:FF:FF:FF:FF (Broadcast)" << std::endl;
    std::cout << "ARP SENDER ||  Source MAC: ";
    for (int i = 0; i < 6; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)senderMac[i];
        if (i < 5) std::cout << ":";
    }
    std::cout << std::dec << std::endl;
    std::cout << "ARP SENDER || Ethernet Type: " << std::hex << replyEthH->ether_type << std::dec << std::endl;

    // Populate ARP header
    replyArpH->ar_hrd = arp_hrd_ethernet;
    replyArpH->ar_pro = htons(ethertype_ip);
    replyArpH->ar_hln = 6;
    replyArpH->ar_pln = 4;
    replyArpH->ar_op = htons(arp_op_request);
    memcpy(replyArpH->ar_sha, senderMac, 6); // Sender MAC address
    replyArpH->ar_sip = htonl(senderIP); // Sender IP address
    memset(replyArpH->ar_tha, 0, 6); // Target MAC address (unknown)
    replyArpH->ar_tip = htonl(targetIP); // Target IP address

    std::cout << "Sender MAC: ";
    for (int i = 0; i < 6; i++) {
        printf("%02x", senderMac[i]); // Print in hex format
        if (i < 5) std::cout << ":";
    }
    std::cout << std::endl;
    std::cout << "Sender IP: " << senderIP << std::endl;

    std::cout << "ARP SENDER ||  ARP Header:" << std::endl;
    std::cout << "ARP SENDER ||  Hardware Type: " << std::hex << replyArpH->ar_hrd << std::dec << std::endl;
    std::cout << "ARP SENDER ||  Protocol Type: " << std::hex << replyArpH->ar_pro << std::dec << std::endl;
    std::cout << "ARP SENDER ||  Hardware Address Length: " << (int)replyArpH->ar_hln << std::endl;
    std::cout << "ARP SENDER ||  Protocol Address Length: " << (int)replyArpH->ar_pln << std::endl;
    std::cout << "ARP SENDER ||  Operation: " << std::hex << replyArpH->ar_op << std::dec << " (ARP request)" << std::endl;

    std::cout << "ARP SENDER ||  Sender MAC: ";
    for (int i = 0; i < 6; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)replyArpH->ar_sha[i];
        if (i < 5) std::cout << ":";
    }
    std::cout << std::dec << std::endl;

    std::cout << "ARP SENDER ||  Sender IP: " << std::dec << ntohl(replyArpH->ar_sip) << std::endl;
    std::cout << "ARP SENDER ||  Target MAC: (unknown, zeroed)" << std::endl;
    std::cout << "ARP SENDER ||  Target IP: " << std::dec << ntohl(replyArpH->ar_tip) << std::endl;
if (packetSender_ == nullptr) {
        std::cout << "Error: packetSender_ is not initialized!" << std::endl;
        return; // Avoid calling sendPacket if packetSender_ is invalid
    }
    // Send the packet
    std::cout << "ARP SENDER || Sending ARP request on interface: " << iface << std::endl;
    try {
        packetSender_->sendPacket(reply, iface);
        std::cout << "packet sent :))" << std::endl;
    } catch (const std::exception& e) {
        std::cout << "Error during sendPacket: " << e.what() << std::endl;
    }
    std::cout << "packet sent :))" << std::endl;
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
