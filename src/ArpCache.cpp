#include "ArpCache.h"

#include <thread>
#include <cstring>
#include <spdlog/spdlog.h>
#include <iostream>

#include "protocol.h"
#include "utils.h"


ArpCache::ArpCache(std::chrono::milliseconds timeout, std::shared_ptr<IPacketSender> packetSender, std::shared_ptr<IRoutingTable> routingTable)
: timeout(timeout)
, packetSender(std::move(packetSender))
, routingTable(std::move(routingTable)) {
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);

    icmpSender = std::make_unique<ICMPSender>(packetSender);
    arpSender = std::make_unique<ARPSender>(packetSender);
}

ArpCache::~ArpCache() {
    shutdown = true;
    if (thread && thread->joinable()) {
        thread->join();
    }
}

void ArpCache::loop() {
    while (!shutdown) {
        tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void ArpCache::tick() {
    std::unique_lock lock(mutex);
    // Your code here
    auto logger = spdlog::get("arp_logger");
    if (!logger) {
        logger = spdlog::default_logger();
    }

    // get the current time
    auto now = std::chrono::steady_clock::now();

    // for each arp request
    for (auto reqIt = requests.begin(); reqIt != requests.end();) {
        ArpRequest& req = reqIt->second;

        // if the last request was sent more than a second ago
        if (now - req.lastSent > std::chrono::seconds(1)) {
            // if the request has been sent more than 7 times
            if (req.timesSent >= 7) {
                logger->warn("ARP request for IP {} failed after {} attempts. Sending ICMP Host Unreachable.",
                             req.ip, req.timesSent);

                // send ICMP "Destination Host Unreachable" to each packet's source
                for (const auto& awaitingPacket : req.awaitingPackets) {
                    // extract original IP header
                    const sr_ip_hdr_t* originalIpHeader = reinterpret_cast<const sr_ip_hdr_t*>(awaitingPacket.packet.data());

                    // srcIp is the IP address of the router interface on which the packet was received or
                    // which would have forwarded the packet.
                    // This represents the "return address" to which the sender will reply
                    uint32_t srcIp = routingTable->getRoutingInterface(awaitingPacket.iface).ip;
                    
                    icmpSender->sendDestinationUnreachable(
                        awaitingPacket.packet,  // Original packet
                        awaitingPacket.iface,   // Outgoing interface
                        srcIp,                  // Source IP
                        static_cast<uint8_t>(ICMPSender::DestinationUnreachableCode::HOST_UNREACHABLE) // ICMP Code
                    );
                }

                // remove the request after sending ICMP errors
                reqIt = requests.erase(reqIt);
                continue; // move to the next request
            // otherwise, retry sending ARP request
            } else {
                logger->info("Retrying ARP request for IP {} (Attempt {}).", req.ip, req.timesSent + 1);
                
                // query the routing table to find the best route for the target IP
                auto route = routingTable->getRoutingEntry(req.ip);
                if (!route) {
                    logger->error("No route found for IP {}.", req.ip);
                    continue;
                } else {
                    // an entry was found
                    RoutingEntry entry = *route;
                    
                    // get the ip of the iface specified by the entry
                    RoutingInterface nextHop = routingTable->getRoutingInterface(entry.iface);
                    std::cout << "Sending packet via interface: " << entry.iface << " to next hop: " << nextHop.ip << std::endl;

                    // resend ARP request
                    arpSender->sendArpRequest(
                        req.ip,      // Target IP address
                        nextHop.ip,      // Sender IP address
                        nextHop.mac.data(),     // Sender MAC address
                        nextHop.name      // Interface to send on
                    );

                    // update retry timestamp and increment times sent
                    req.lastSent = std::chrono::steady_clock::now();
                    req.timesSent++;
                }
            }
        }
    }

    // Your code should end here

    // Remove entries that have been in the cache for too long
    std::erase_if(entries, [this](const auto& entry) {
        bool expired = std::chrono::steady_clock::now() - entry.second.timeAdded >= timeout;
        if (expired) {
            logger->info("Removing expired ARP cache entry for IP {}.", entry.first);
        }
        return expired;
    });

    logger->info("Finished processing ARP requests and cache maintenance.");
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);

    // add the IP-MAC mapping to the ARP cache
    entries[ip] = {ip, mac, std::chrono::steady_clock::now()};

    // check if there are pending packets for this IP
    auto it = requests.find(ip);

    // if there are pending packets
    if (it != requests.end()) {
        // send all queued packets using the packet sender
        for (const auto& awaitingPacket : it->second.awaitingPackets) {
            packetSender->sendPacket(awaitingPacket.packet, awaitingPacket.iface);
        }

        // remove the ARP request from the queue
        requests.erase(it);
    }
}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);

    // check if there is already an entry for this IP
    auto it = entries.find(ip);

    // if the IP address exists in the ARP cache
    if (it != entries.end()) {
        // return the associated MAC address
        return it->second.mac;
    }

    // if the IP address doesn't exist in the ARP cache, return an empty optional
    return std::nullopt;
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);

    // check if there is already an ARP request for this IP
    auto it = requests.find(ip);

    // if no ARP request exists for this IP
    if (it == requests.end()) {
        // create a new ARP request
        ArpRequest newRequest{ip, std::chrono::steady_clock::now(), 0, {}};
        newRequest.awaitingPackets.emplace_back(packet, iface);

        // add the new ARP request to the map
        requests[ip] = std::move(newRequest);
    }
    // ARP request exists
    else {
        // queue the packet to the existing request
        it->second.awaitingPackets.emplace_back(packet, iface);
    }

}
