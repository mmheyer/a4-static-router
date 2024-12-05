#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>
#include <iostream>
#include "protocol.h"
#include "utils.h"
#include "RoutingTable.h"
#include "ICMPSender.h"

StaticRouter::StaticRouter(std::unique_ptr<IArpCache> arpCache, std::shared_ptr<IRoutingTable> routingTable,
                           std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable)
      , packetSender(packetSender)
      , arpCache(std::move(arpCache))
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

    auto* ethHeader = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    uint16_t etype = ntohs(ethHeader->ether_type);

    std::cout << "\n *** Ethernet Header ***" << std::endl;
    std::cout << "Ethernet Type: " << std::hex << etype << std::dec << std::endl;
    std::cout << "Destination MAC: ";
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        std::cout << std::hex << (int)ethHeader->ether_dhost[i] << (i < ETHER_ADDR_LEN - 1 ? ":" : "");
    }
    std::cout << std::endl;
    std::cout << "Source MAC: ";
    for (int i = 0; i < ETHER_ADDR_LEN; i++) {
        std::cout << std::hex << (int)ethHeader->ether_shost[i] << (i < ETHER_ADDR_LEN - 1 ? ":" : "");
    }
    std::cout << std::endl;

    if(etype == ethertype_arp){
        handleARP(packet, iface, ethHeader);
    } else if(etype == ethertype_ip){
       handleIP(packet, iface, ethHeader);
    } 
   else{
        spdlog::error("Unsupported EtherType: {:#06x}", etype);
    }

}

void StaticRouter::handleARP(std::vector<uint8_t> &packet, std::string &iface, sr_ethernet_hdr_t *ethHeader){
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
        //  virtual void addEntry(uint32_t ip, const mac_addr &mac) = 0;
        arpCache->addEntry(arpHeader->ar_sip, macAddr);
        spdlog::info("ARP cache updated with IP: {:#08x}", ntohl(arpHeader->ar_sip));
    } else if(op == arp_op_request){
        std::cout << "REQUEST" << std::endl;
        spdlog::info("Received ARP Request");
        

        std::cout << "Route found :) " << std::endl;
        spdlog::info("This router owns the requested IP.");
        //arp reply 
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


void StaticRouter::handleIP(std::vector<uint8_t>& packet, const std::string& iface, sr_ethernet_hdr_t* ethHeader) {
    std::cout << "[IP] handleIP" << std::endl;
    // Check if packet contains an IP header
    if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        spdlog::error("Packet is too small to contain an IP header.");
        return;
    }

    // Extract IP header
    auto* ipHeader = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    // Verify checksum
    uint16_t originalChecksum = ipHeader->ip_sum;
    ipHeader->ip_sum = 0;
    uint16_t calculatedChecksum = cksum(reinterpret_cast<uint16_t*>(ipHeader), sizeof(sr_ip_hdr_t));
    ipHeader->ip_sum = originalChecksum;  // Restore original checksum
    if (calculatedChecksum != originalChecksum) {
        spdlog::error("Invalid IP checksum. Dropping packet.");
        return;
    }
    std::cout << "[IP] checksum verified" << std::endl;
     // Print IP header (assuming sr_ip_hdr_t is a struct with IP addresses and protocol)
    std::cout << "[IP Header] Source IP: " << (int)(ipHeader->ip_src)<< std::endl;
    std::cout << "[IP Header] Destination IP: " << (int)(ipHeader->ip_dst) << std::endl;
    std::cout << "[IP Header] Protocol: " << (int)(ipHeader->ip_p) << std::endl;
    std::cout << "[IP Header] Total Length: " << (int)(ipHeader->ip_len)  << std::endl;
    // Check if the destination IP matches one of the router's interfaces
    // Check if the destination IP matches one of the router's interfaces
   // Check if the destination IP matches one of the router's interfaces
    for (const auto& [ifaceName, ifaceInfo] : routingTable->getRoutingInterfaces()) {
        std::cout << "dest ip : " << ipHeader->ip_dst << " " << "ntohl " << ntohl(ipHeader->ip_dst) << std::endl;
        std::cout << "iface ip : " << ifaceInfo.ip << " " << "ntohl " << ntohl(ifaceInfo.ip) << std::endl;
        if (ipHeader->ip_dst == ntohl(ifaceInfo.ip)) {
            if(ipHeader->ip_p == ip_protocol_icmp){
            // Destination IP matches the router's interface IP
                std::cout << "ECHO" << std::endl;
                handleICMPEchoRequest(packet, iface, ethHeader);
            } else {
                // Forward the packet or handle as unreachable
                std::cout << "Destination Unreachable" << std::endl;
                icmpSender->sendDestinationUnreachable(packet, iface, ifaceInfo.ip, 3 /* Port Unreachable */);
            }
        return;
        }
        
    }

    // Forward the packet if destination IP is not one of the router's interfaces
    std::cout << "forward" << std::endl;
    spdlog::info("Destination IP does not match any router interface. Forwarding packet.");
    forwardIPPacket(packet, iface, ethHeader, ipHeader);
   // handleICMPEchoRequest(packet, iface, ethHeader);

}

void StaticRouter::sendDestinationUnreachable(const std::vector<uint8_t>& packet,
                                            const std::string& iface,
                                            uint32_t sourceIP,
                                            uint8_t icmpCode) {
                                                std::cout << "[InDESTUNREACHABLE]" << std::endl;
    uint32_t destIP = *reinterpret_cast<const uint32_t*>(&packet[12]); // Source IP from the original packet
   }

void StaticRouter::forwardIPPacket(std::vector<uint8_t>& packet, const std::string& iface,
                                   sr_ethernet_hdr_t* ethHeader, sr_ip_hdr_t* ipHeader) {
    std::cout << "*** wip in forwardip packet" << std::endl;


    // Print IP header (assuming sr_ip_hdr_t is a struct with IP addresses and protocol)
    std::cout << "[IP Header] Source IP: " << (int)(ipHeader->ip_src)<< std::endl;
    std::cout << "[IP Header] Destination IP: " << (int)(ipHeader->ip_dst) << std::endl;
    std::cout << "[IP Header] Protocol: " << (int)(ipHeader->ip_p) << std::endl;
    std::cout << "[IP Header] Total Length: " << (int)(ipHeader->ip_len)  << std::endl;

    
    // Decrement TTL and recompute checksum
    ipHeader->ip_ttl--;
    if (ipHeader->ip_ttl == 0) {
        std::cout << "[FORWARD IP] ttl = 0" << std::endl;
        icmpSender->sendTimeExceeded(packet, iface, ntohl(ipHeader->ip_src));
        return;
    }
    ipHeader->ip_sum = 0;
    ipHeader->ip_sum = cksum(ipHeader, sizeof(sr_ip_hdr_t));

    // Lookup routing table
    auto route = routingTable->getRoutingEntry(ntohl(ipHeader->ip_dst));
    if (!route) {
        std::cout << "[FORWARD IP] dest unreachable in forwarding" << std::endl;
        icmpSender->sendDestinationUnreachable(packet, iface, ntohl(ipHeader->ip_src), 0 ); // Network Unreachable 
        return;
    }
    std::cout << "[FORWARD IP] forwarding route found" << std::endl;

    // Check ARP cache for next-hop MAC
    auto nextHopMAC = arpCache->getEntry(route->gateway);
    if (nextHopMAC) {
        std::cout << "[FORWARD IP] next hop" << std::endl;
        // Update Ethernet header with next-hop MAC and router's MAC
        std::memcpy(ethHeader->ether_dhost, nextHopMAC->data(), ETHER_ADDR_LEN);
        std::memcpy(ethHeader->ether_shost, routingTable->getRoutingInterface(route->iface).mac.data(), ETHER_ADDR_LEN);
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
                                         sr_ethernet_hdr_t* ethHeader) {
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
    std::swap(ethHeader->ether_dhost, ethHeader->ether_shost); // swap MAC addresses

    packetSender->sendPacket(packet, iface);
}
