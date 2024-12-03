#ifndef STATICROUTER_H
#define STATICROUTER_H
#include <vector>
#include <memory>
#include <mutex>

#include "IArpCache.h"
#include "IPacketSender.h"
#include "IRoutingTable.h"
#include "ICMPSender.h"
#include "ARPSender.h"


class StaticRouter {
public:
    StaticRouter(std::unique_ptr<IArpCache> arpCache, std::shared_ptr<IRoutingTable> routingTable,
                 std::shared_ptr<IPacketSender> packetSender);

    void handleARP(std::vector<uint8_t>& packet, std::string& iface, sr_ethernet_hdr_t* ethHeader);

    /**
     * @brief Handles an incoming packet, telling the switch to send out the necessary packets.
     * @param packet The incoming packet.
     * @param iface The interface on which the packet was received.
     */
    void handlePacket(std::vector<uint8_t> packet, std::string iface);

private:
    void handleIP(std::vector<uint8_t>& packet, const std::string& iface, sr_ethernet_hdr_t* ethHeader);
    void forwardIPPacket(std::vector<uint8_t>& packet, const std::string& iface, sr_ethernet_hdr_t* ethHeader, sr_ip_hdr_t* ipHeader);
    void handleICMPEchoRequest(std::vector<uint8_t>& packet, const std::string& iface, sr_ethernet_hdr_t* ethHeader);

    std::mutex mutex;
    std::shared_ptr<IRoutingTable> routingTable; // Routing table for forwarding decisions
    std::shared_ptr<IPacketSender> packetSender; // Interface for sending packets
    std::unique_ptr<IArpCache> arpCache; // ARP cache for resolving ip-to-mac mappings

    std::shared_ptr<ICMPSender> icmpSender; // Sends ICMP error and echo reply msgs
    std::shared_ptr<ARPSender> arpSender; // Sends ARP reqs and replies.
};


#endif //STATICROUTER_H
