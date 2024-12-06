#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>
#include <iostream>
#include <cstring>
#include <optional>
#include "protocol.h"
#include "utils.h"
#include "RoutingTable.h"
#include "ICMPSender.h"

StaticRouter::StaticRouter(std::unique_ptr<IArpCache> arpCache, std::shared_ptr<IRoutingTable> routingTable,
                           std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable)
      , packetSender(packetSender)
      , arpCache(std::move(arpCache))
      , arpSender(std::make_shared<ARPSender>(this->packetSender))
{
}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface)
{
    std::unique_lock lock(mutex);

    if (packet.size() < sizeof(sr_ethernet_hdr_t))
    {
        spdlog::error("Packet is too small to contain an Ethernet header.");
        return;
    }

    //extract ethernet header
    std::cout << "\n *** Packet received on interface: " << iface << " ***" << std::endl;
    std::cout << "Packet size: " << packet.size() << " bytes" << std::endl;
    for(auto x: packet){
        std::cout << x << " ";
    }
    std::cout << std::endl;
    std::cout << "Packet data: ";
    for (size_t i = 0; i < packet.size(); ++i) {
        std::cout << std::hex << (int)packet[i] << " ";
        if ((i + 1) % 16 == 0) {  // Format it with 16 bytes per line
            std::cout << std::endl;
        }
    }
    std::cout << std::dec << std::endl;

    // auto* ethernet_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    sr_ethernet_hdr_t *ethernet_hdr = reinterpret_cast<sr_ethernet_hdr_t *>(packet.data());
    uint16_t etype = ntohs(ethernet_hdr->ether_type);

    std::cout << "\n *** Ethernet Header ***" << std::endl;
    std::cout << "Ethernet Type: " << std::hex << etype << std::dec << std::endl;
    std::cout << "Destination MAC: ";
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        std::cout << std::hex << (int)ethernet_hdr->ether_dhost[i] << (i < ETHER_ADDR_LEN - 1 ? ":" : "");
    }
    std::cout << std::endl;
    std::cout << "Source MAC: ";
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        std::cout << std::hex << (int)ethernet_hdr->ether_shost[i] << (i < ETHER_ADDR_LEN - 1 ? ":" : "");
    }
    std::cout << std::endl;

    if(etype == ethertype_arp){
        handleARP(packet, iface, ethernet_hdr);
    } else if(etype == ethertype_ip){
       handleIP(packet, iface, ethernet_hdr);
    }
   else{
        spdlog::error("Unsupported EtherType: {:#06x}", etype);
    }

}

void StaticRouter::handleARP(std::vector<uint8_t> &packet, std::string &iface, sr_ethernet_hdr_t *ethernet_hdr){
    std::cout << "handleARP" << std::endl;
    //constexpr inline size_t ARP_PACKET_SIZE = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    if(packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)){
        spdlog::error("Packet not large enough to contain ARP.");
        return; 
    }

    auto *arpHeader = reinterpret_cast<sr_arp_hdr_t *>(packet.data() + sizeof(sr_ethernet_hdr_t));
    // Print ARP header information
    std::cout << "\n *** ARP Header ***" << std::endl;
    std::cout << "ARP Operation: " << std::hex << ntohs(arpHeader->ar_op) << std::dec << std::endl;
    std::cout << "Sender MAC: ";
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        std::cout << std::hex << (int)arpHeader->ar_sha[i] << (i < ETHER_ADDR_LEN - 1 ? ":" : "");
    }
    std::cout << std::endl;
    std::cout << "Sender IP: " << std::dec << ntohl(arpHeader->ar_sip) << std::endl;
    std::cout << "Target MAC: ";
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        std::cout << std::hex << (int)arpHeader->ar_tha[i] << (i < ETHER_ADDR_LEN - 1 ? ":" : "");
    }
    std::cout << std::endl;
    std::cout << "Target IP: " <<  std::dec << ntohl(arpHeader->ar_tip) << std::endl;

    
    
    unsigned short op = ntohs(arpHeader->ar_op);
    std::array<unsigned char, 6> macAddr;
    std::copy(std::begin(arpHeader->ar_sha), std::end(arpHeader->ar_sha), macAddr.begin());

    if(op == arp_op_reply){
        std::cout << "REPLY" << std::endl;
        spdlog::info("Received ARP reply.");

        // Check if the ARP cache has an entry or a pending request for this IP
        auto entry = arpCache->getEntry(arpHeader->ar_sip);
        if (entry == std::nullopt) {
            spdlog::warn("Unsolicited ARP reply received for IP: {:#08x}. Ignoring.", ntohl(arpHeader->ar_sip));
            return; // Exit without processing the reply further
        }

        // Add the ARP entry and process pending requests
        arpCache->addEntry(arpHeader->ar_sip, macAddr);
        spdlog::info("ARP cache updated with IP: {:#08x}", ntohl(arpHeader->ar_sip));
    } else if(op == arp_op_request){
        std::cout << "REQUEST" << std::endl;
        spdlog::info("Received ARP Request");
        

        std::cout << "Route found :) " << std::endl;
        spdlog::info("This router owns the requested IP.");
        
        //arp reply 
        RoutingInterface currentInterface = routingTable->getRoutingInterface(iface);
        if (currentInterface.ip != arpHeader->ar_tip) {
            std::cout << "Dropping Packet: Target IP does not match receiving interface IP" << std::endl;
            spdlog::info("Dropping Packet: Target IP {} does not match receiving interface IP {}", 
                        ntohl(arpHeader->ar_tip), ntohl(currentInterface.ip));
            return;
        }
        bool isTargetIpOwned = false;
        for (const auto& [ifaceName, ifaceInfo] : routingTable->getRoutingInterfaces()) {
            if (ifaceInfo.ip == arpHeader->ar_tip) {
                isTargetIpOwned = true;
                break;
            }
        }
        if (!isTargetIpOwned) {
            std::cout << "Dropping Packet: Target IP not owned by router" << std::endl;
            spdlog::info("Dropping Packet: Target IP {:#08x} not owned by router", ntohl(arpHeader->ar_tip));
            return;
        }

        // Construct ARP reply packet
        std::vector<uint8_t> reply(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
        auto *replyEthH = reinterpret_cast<sr_ethernet_hdr_t *>(reply.data());
        auto *replyArpH = reinterpret_cast<sr_arp_hdr_t *>(reply.data() + sizeof(sr_ethernet_hdr_t));

        RoutingInterface RI = routingTable->getRoutingInterface(iface);                 // Source(router's MAC for the interface)
        std::memcpy(replyEthH->ether_dhost, arpHeader->ar_sha, ETHER_ADDR_LEN); // Target (source of the request)
        std::memcpy(replyEthH->ether_shost, RI.mac.data(), ETHER_ADDR_LEN); // (router's MAC)

        replyEthH->ether_type = htons(ethertype_arp);

        replyArpH->ar_op = htons(arp_op_reply);
        replyArpH->ar_hrd = htons(arp_hrd_ethernet); 
        replyArpH->ar_pro = htons(ethertype_ip);
        replyArpH->ar_hln = ETHER_ADDR_LEN;
        replyArpH->ar_pln = 4;

        std::memcpy(replyArpH->ar_sha, replyEthH->ether_shost, ETHER_ADDR_LEN);
        std::memcpy(replyArpH->ar_tha, arpHeader->ar_sha, ETHER_ADDR_LEN);
        replyArpH->ar_tip = arpHeader->ar_sip; 
        replyArpH->ar_sip = arpHeader->ar_tip;

        std::cout << "iface info for reply" << std::endl;
        std::cout << "name: " << iface << std::endl;

                std::cout << "\n *** RESPONSE PACKET: ARP Header ***" << std::endl;
                std::cout << "ARP Operation: " << std::hex << ntohs(replyArpH->ar_op) << std::dec << std::endl;
                std::cout << "Sender MAC: ";
                for (int i = 0; i < ETHER_ADDR_LEN; i++) {
                    std::cout << std::hex << (int)replyArpH->ar_sha[i] << (i < ETHER_ADDR_LEN - 1 ? ":" : "");
                }
                std::cout << std::endl;
                std::cout << "Sender IP: " << std::dec << ntohl(replyArpH->ar_sip) << std::endl;
                std::cout << "Target MAC: ";
                for (int i = 0; i < ETHER_ADDR_LEN; i++) {
                    std::cout << std::hex << (int)replyArpH->ar_tha[i] << (i < ETHER_ADDR_LEN - 1 ? ":" : "");
                }
                std::cout << std::endl;
                std::cout << "Target IP: " << std::dec << ntohl(replyArpH->ar_tip) << std::endl;

                
        // Send ARP reply
        
        packetSender->sendPacket(reply, iface);
        spdlog::info("ARP reply sent to IP: {:#08x}", ntohl(arpHeader->ar_sip));
        std::cout << "reply sent" << std::endl;

    } else{
         spdlog::error("Unsupported ARP Op: {:#06x}", ntohs(arpHeader->ar_op));
    }
}


void StaticRouter::handleIP(std::vector<uint8_t>& packet, const std::string& iface, sr_ethernet_hdr_t* ethernet_hdr) {
    spdlog::debug("Handling IP packet.");

    // Check if packet contains an IP header
    if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        spdlog::error("Packet is too small to contain an IP header.");
        return;
    }

    // Extract IP header
    // auto* ipHeader = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t *ipHeader = reinterpret_cast<sr_ip_hdr_t *>(packet.data() + sizeof(sr_ethernet_hdr_t));

    uint8_t *payload = packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    size_t payload_len = ntohs(ipHeader->ip_len) - sizeof(sr_ip_hdr_t);

    // Verify checksum
    uint16_t originalChecksum = ipHeader->ip_sum;
    ipHeader->ip_sum = 0;
    uint16_t calculatedChecksum = cksum(reinterpret_cast<uint16_t*>(ipHeader), sizeof(sr_ip_hdr_t));
    ipHeader->ip_sum = originalChecksum;  // Restore original checksum
    if (calculatedChecksum != originalChecksum) {
        spdlog::error("Invalid IP checksum. Dropping packet.");
        return;
    }
    spdlog::debug("[IP] checksum verified");

    // Print IP header (assuming sr_ip_hdr_t is a struct with IP addresses and protocol)
    std::cout << "[IP Header] Source IP: " << (int)(ipHeader->ip_src)<< std::endl;
    std::cout << "[IP Header] Destination IP: " << (int)(ipHeader->ip_dst) << std::endl;
    std::cout << "[IP Header] Protocol: " << (int)(ipHeader->ip_p) << std::endl;
    std::cout << "[IP Header] Total Length: " << (int)(ipHeader->ip_len)  << std::endl;

    // // The source MAC address should be the MAC address of the router’s interface that is sending the ICMP message.
	// // This is the MAC address associated with the interface on which the original packet was received.
    // mac_addr icmpSourceMAC = routingTable->getRoutingInterface(iface).mac;

    // // The destination MAC address should be the MAC address of the device that sent the original packet (i.e., the packet that triggered the ICMP message).
	// // This is typically the source MAC address from the original Ethernet header.
    // mac_addr icmpDestMAC = extractSourceMAC(packet);

    // // The source IP address should be the IP address of the router’s interface that is sending the ICMP message.
	// // This is the IP address associated with the interface on which the original packet was received.
    // ip_addr icmpSourceIP = routingTable->getRoutingInterface(iface).ip;

    // // The destination IP address should be the source IP address from the original packet’s IP header.
	// // This is the IP address of the device that sent the packet which caused the ICMP message to be generated.
    // ip_addr icmpDestIP = ipHeader->ip_src;

    // for each interface in the routing table
    for (const auto& [ifaceName, ifaceInfo] : routingTable->getRoutingInterfaces()) {
        std::cout << "dest ip : " << ipHeader->ip_dst << " " << "ntohl " << ntohl(ipHeader->ip_dst) << std::endl;
        std::cout << "iface ip : " << ifaceInfo.ip << " " << "ntohl " << ntohl(ifaceInfo.ip ) << std::endl;
        const uint32_t mask = 0xFFFFFF00;
        std::cout << " --------> " << (ntohl(ipHeader->ip_dst) & mask) << " " <<(ntohl(ifaceInfo.ip) & mask) << std::endl;

        // if the destination ip matches this interface
        if ((ntohl(ipHeader->ip_dst) & mask) == (ntohl(ifaceInfo.ip) & mask)) {
             // if the packet contains an icmp message
             if(ipHeader->ip_p == ip_protocol_icmp){
                // the packet is an ICMP ECHO request
                std::cout << "ECHO" << std::endl;
                handleICMPEchoRequest(packet, iface, ethernet_hdr);
            } 
            // if the packet contains a TCP or UDP payload
            else if (ipHeader->ip_p == ip_protocol_tcp || ipHeader->ip_p == ip_protocol_udp) {
                spdlog::info("Packet contains TCP or UDP payload. Sending ICMP port unreachable.");
                // icmpSender->sendPortUnreachable(packet, icmpSourceMAC, icmpSourceIP, icmpDestMAC, icmpDestIP, iface);
                sendIcmpMessage(3, 3, ipHeader, payload, payload_len, iface);
            }
            // otherwise, discard the packet
            return;
        }
    }

    // otherwise, the frame contains an IP packet whose destination is not one of the router's interfaces
    // if the packet's ttl is already 0, we should drop it
    if (ipHeader->ip_ttl <= 0) return;

    // decrement ttl
    ipHeader->ip_ttl--;

    // if the ttl is 0
    if (ipHeader->ip_ttl == 0) {
        spdlog::info("TTL = 0. Sending ICMP time exceeded.");
        // icmpSender->sendTimeExceeded(packet, icmpSourceMAC, icmpSourceIP, icmpDestMAC, icmpDestIP, iface);
        sendIcmpMessage(11, 0, ipHeader, payload, payload_len, iface);
        return;
    }

    // set checksum to 0
    ipHeader->ip_sum = 0;

    // recompute checksum
    ipHeader->ip_sum = cksum(ipHeader, sizeof(ipHeader));

    // find out which entry in the routing table has the longest prefix match with the destination IP address
    auto route = routingTable->getRoutingEntry(ipHeader->ip_dst);

    // if there is no route to the destination network
    if (route == std::nullopt) {
        spdlog::info("No route to network. Sending ICMP destination unreachable.");
        // icmpSender->sendDestinationUnreachable(packet, icmpSourceMAC, icmpSourceIP, icmpDestMAC, icmpDestIP, iface, ICMPSender::DestinationUnreachableCode::NET_UNREACHABLE);
        sendIcmpMessage(3, 0, ipHeader, payload, payload_len, iface);
        return;
    }

    // check ARP cache for the next hop
    auto nextHopMac = arpCache->getEntry(route->gateway);

    // if entry is in the ARP cache
    if (nextHopMac != std::nullopt) {
        spdlog::info("Destination IP does not match any router interface. Forwarding packet.");
        forwardIPPacket(packet, iface, ethernet_hdr, ipHeader);
        return;
    }

    // send an ARP request for the next-hop IP (if one hasn't been sent within the last second), 
    // and add the packet to the queue of packets waiting on this ARP request
    arpCache->queuePacket(route->gateway, packet, iface);
}



void StaticRouter::forwardIPPacket(std::vector<uint8_t>& packet, const std::string& iface,
                                   sr_ethernet_hdr_t* ethernet_hdr, sr_ip_hdr_t* ipHeader) {
    std::cout << "*** wip in forwardip packet" << std::endl;


    // Print IP header (assuming sr_ip_hdr_t is a struct with IP addresses and protocol)
    std::cout << "[IP Header] Source IP: " << (int)(ipHeader->ip_src)<< std::endl;
    std::cout << "[IP Header] Destination IP: " << (int)(ipHeader->ip_dst) << std::endl;
    std::cout << "[IP Header] Protocol: " << (int)(ipHeader->ip_p) << std::endl;
    std::cout << "[IP Header] Total Length: " << (int)(ipHeader->ip_len)  << std::endl;

    uint8_t *payload = packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    size_t payload_len = ntohs(ipHeader->ip_len) - sizeof(sr_ip_hdr_t);

    // Decrement TTL and recompute checksum
    ipHeader->ip_ttl--;
    if (ipHeader->ip_ttl <= 0) {
        std::cout << "[FORWARD IP] ttl = 0" << std::endl;
         mac_addr sourceMAC = extractSourceMAC(packet);
         mac_addr destMAC = extractSourceMAC(packet);

        // icmpSender->sendTimeExceeded(packet, sourceMAC, ipHeader->ip_src, destMAC, ipHeader->ip_dst, iface);
        sendIcmpMessage(11, 0, ipHeader, payload, payload_len, iface); // Time Exceeded
        return;
    }
    ipHeader->ip_sum = 0;
    ipHeader->ip_sum = cksum(ipHeader, sizeof(sr_ip_hdr_t));

    // Lookup routing table
    auto route = routingTable->getRoutingEntry(ntohl(ipHeader->ip_dst));
    if (!route) {
        std::cout << "[FORWARD IP] dest unreachable in forwarding" << std::endl;
         mac_addr sourceMAC = extractSourceMAC(packet);
        mac_addr destMAC = extractSourceMAC(packet);

         // Call sendDestinationUnreachable
         // icmpSender->sendDestinationUnreachable(packet, sourceMAC, ipHeader->ip_src, destMAC, ipHeader->ip_dst, iface, ICMPSender::DestinationUnreachableCode::NET_UNREACHABLE);
        sendIcmpMessage(3, 0, ipHeader, payload, payload_len, iface);
        return;
    }
    std::cout << "[FORWARD IP] forwarding route found" << std::endl;

    // Check ARP cache for next-hop MAC
    auto nextHopMAC = arpCache->getEntry(route->gateway);
    if (nextHopMAC) {
        std::cout << "[FORWARD IP] next hop" << std::endl;
        // Update Ethernet header with next-hop MAC and router's MAC
        std::memcpy(ethernet_hdr->ether_dhost, nextHopMAC->data(), ETHER_ADDR_LEN);
        std::memcpy(ethernet_hdr->ether_shost, routingTable->getRoutingInterface(route->iface).mac.data(), ETHER_ADDR_LEN);
        std::cout << "next hop pkt sent" << std::endl;
        packetSender->sendPacket(packet, route->iface);
    } else {
        std::cout << "[FORWARD IP] queue" << std::endl;
        // Queue the packet and send ARP request
        arpCache->queuePacket(route->gateway, packet, route->iface);
        std::cout << "[FORWARD IP] send arp req" << std::endl;
        std::cout << "------------------------------------------------FORWARDIP" << std::endl;
        arpSender->sendArpRequest(route->gateway, routingTable->getRoutingInterface(route->iface).ip,
                                 routingTable->getRoutingInterface(route->iface).mac.data(), route->iface);
        std::cout << "------------------------------------------------FORWARDIP END" << std::endl;

      
    }
}

void StaticRouter::handleICMPEchoRequest(std::vector<uint8_t>& packet, const std::string& iface,
                                         sr_ethernet_hdr_t* ethernet_hdr) {
    //  ICMP header and validate
    std::cout << "ICMP ECHO" << std::endl;
    auto* icmpHeader = reinterpret_cast<sr_icmp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    if (icmpHeader->icmp_type != 8 ) {// /Echo Request 
        spdlog::error("Unsupported ICMP type. Dropping packet.");
        return;
    }

    //  ICMP Echo Reply
    auto* ipHeader = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    
    uint32_t tempIP = ipHeader->ip_src;
    ipHeader->ip_src = ipHeader->ip_dst;
    ipHeader->ip_dst = tempIP; // swap source and destination IPs

    ipHeader->ip_ttl = 64; // reset TTL
    ipHeader->ip_sum = 0; //  IP checksum
    ipHeader->ip_sum = cksum(reinterpret_cast<uint16_t*>(ipHeader), sizeof(sr_ip_hdr_t));

    icmpHeader->icmp_type = 0; //  Reply
    icmpHeader->icmp_code = 0; 
    icmpHeader->icmp_sum = 0; // clear checksum field
    size_t icmpPayloadSize = packet.size() - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmpHeader->icmp_sum = cksum(reinterpret_cast<uint16_t*>(icmpHeader), icmpPayloadSize);

    //  Ethernet header
    std::swap(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost); // swap MAC addresses

    packetSender->sendPacket(packet, iface);
}

Packet StaticRouter::createPacket(const sr_ip_hdr_t *ipHeader, const uint8_t *payload, size_t payload_len) {
    Packet packet(sizeof(sr_ip_hdr_t) + payload_len);
    memcpy(packet.data(), ipHeader, sizeof(sr_ip_hdr_t));
    memcpy(packet.data() + sizeof(sr_ip_hdr_t), payload, payload_len);
    return packet;
}

void StaticRouter::sendIcmpMessage(uint8_t type, uint8_t code, const sr_ip_hdr_t *original_ip_hdr,
                        const uint8_t *payload, size_t payload_len, const std::string &out_iface) {
    size_t icmp_len = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    Packet packet(sizeof(sr_ethernet_hdr_t) + icmp_len);

    // Ethernet header
    sr_ethernet_hdr_t *ethernet_hdr = reinterpret_cast<sr_ethernet_hdr_t *>(packet.data());
    memset(ethernet_hdr, 0, sizeof(sr_ethernet_hdr_t));

    // Set source MAC address (router's MAC address for out_iface)
    auto src_mac = routingTable->getRoutingInterface(out_iface); // Function that returns MAC address for out_iface
    if (std::all_of(src_mac.mac.begin(), src_mac.mac.end(), [](unsigned char c) { return c == 0; })) {
        spdlog::error("MAC address is all zeroes.");
        return; // Handle error
    }
    spdlog::info("Source MAC: {}", fmt::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
    src_mac.mac[0], src_mac.mac[1], src_mac.mac[2], src_mac.mac[3], src_mac.mac[4], src_mac.mac[5]));
    memcpy(ethernet_hdr->ether_shost, src_mac.mac.data() ,ETHER_ADDR_LEN); // Set source MAC


     // Set destination MAC address
    auto routing_entry = routingTable->getRoutingEntry(original_ip_hdr->ip_src); // Get routing entry for sender's IP
    if (!routing_entry) {
        spdlog::error("Failed to find routing entry for IP {}", original_ip_hdr->ip_src);
        return; // Handle error (e.g., drop packet or handle ARP)
    }

    // Get the MAC address for the destination IP (from the routing entry)
    auto dest_routing_iface = routingTable->getRoutingInterface(routing_entry->iface); 
    memcpy(ethernet_hdr->ether_dhost, dest_routing_iface.mac.data(), ETHER_ADDR_LEN); // Set destination MAC


    // Set ether type 
    ethernet_hdr->ether_type = htons(ethertype_ip);

    // IP header
    sr_ip_hdr_t *ipHeader = reinterpret_cast<sr_ip_hdr_t *>(packet.data() + sizeof(sr_ethernet_hdr_t));
    memset(ipHeader, 0, sizeof(sr_ip_hdr_t));
    ipHeader->ip_hl = 5;
    ipHeader->ip_v = 4;
    ipHeader->ip_tos = 0;
    ipHeader->ip_len = htons(icmp_len);
    ipHeader->ip_id = htons(0);
    ipHeader->ip_off = htons(0);
    ipHeader->ip_ttl = 64;
    ipHeader->ip_p = ip_protocol_icmp;
    ipHeader->ip_src = original_ip_hdr->ip_dst; // Router's IP
    ipHeader->ip_dst = original_ip_hdr->ip_src; // Sender's IP
    ipHeader->ip_sum = 0;
    ipHeader->ip_sum = cksum(ipHeader, sizeof(sr_ip_hdr_t));

    // ICMP header
    sr_icmp_t3_hdr_t *icmp_hdr = reinterpret_cast<sr_icmp_t3_hdr_t *>(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    memset(icmp_hdr, 0, sizeof(sr_icmp_t3_hdr_t));
    icmp_hdr->icmp_type = type;
    icmp_hdr->icmp_code = code;
    memcpy(icmp_hdr->data, original_ip_hdr, sizeof(sr_ip_hdr_t) + 8); // Include original IP header and 8 bytes of payload
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

    // Send the packet
    packetSender->sendPacket(packet, out_iface);
}