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

    spdlog::info("Initialized ArpCache with timeout {} ms.", timeout.count());
}

ArpCache::~ArpCache() {
    shutdown = true;
    if (thread && thread->joinable()) {
        thread->join();
    }
    spdlog::info("ArpCache shutdown complete.");
}

void ArpCache::loop() {
    while (!shutdown) {
        tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void ArpCache::tick() {
    std::unique_lock lock(mutex);
    auto logger = spdlog::get("arp_logger");
    if (!logger) {
        logger = spdlog::default_logger();
    }

    auto now = std::chrono::steady_clock::now();

    // Iterate over all ARP requests
    for (auto reqIt = requests.begin(); reqIt != requests.end();) {
        ArpRequest& req = reqIt->second;

        if (now - req.lastSent > std::chrono::seconds(1)) {
            if (req.timesSent >= 7) {
                logger->warn("ARP request for IP {} failed after {} attempts. Sending ICMP Host Unreachable.", req.ip, req.timesSent);

                // Send ICMP Host Unreachable for each awaiting packet
                for (const auto& awaitingPacket : req.awaitingPackets) {
                    try {
                        // Extract source IP and MAC from the original packet
                        uint32_t sourceIP = extractSourceIP(awaitingPacket.packet);
                        mac_addr sourceMAC = extractSourceMAC(awaitingPacket.packet);

                        // Get routing interface for the source IP
                        auto route = routingTable->getRoutingEntry(sourceIP);
                        if (!route) {
                            logger->error("No routing entry found for source IP {}.", sourceIP);
                            continue;
                        }

                        // Get routing interface details
                        auto iface = routingTable->getRoutingInterface(route->iface);
                        uint32_t ifaceIP = iface.ip;
                        mac_addr ifaceMAC = iface.mac;

                        // Extract destination IP and pass along awaitingPacket.iface
                        uint32_t destIP = extractDestinationIP(awaitingPacket.packet);

                        // Send ICMP Destination Host Unreachable
                        icmpSender->sendDestinationUnreachable(
                            awaitingPacket.packet, ifaceMAC, ifaceIP, sourceMAC, sourceIP, awaitingPacket.iface,
                            ICMPSender::DestinationUnreachableCode::HOST_UNREACHABLE);
                    } catch (const std::exception& e) {
                        logger->error("Error while sending ICMP Host Unreachable: {}", e.what());
                    }
                }

                // Erase the ARP request after sending ICMP errors
                reqIt = requests.erase(reqIt);
                continue;

            } else {
                logger->info("Retrying ARP request for IP {} (Attempt {}).", req.ip, req.timesSent + 1);

                auto route = routingTable->getRoutingEntry(req.ip);
                if (!route) {
                    logger->error("No route found for target IP {}.", req.ip);
                    ++reqIt;
                    continue;
                }

                auto iface = routingTable->getRoutingInterface(route->iface);
                arpSender->sendArpRequest(req.ip, iface.ip, iface.mac.data(), iface.name);

                req.lastSent = now;
                req.timesSent++;
            }
        }
        ++reqIt;
    }

    // Remove expired ARP cache entries
    std::erase_if(entries, [this, now, logger](const auto& entry) {
        bool expired = now - entry.second.timeAdded >= timeout;
        if (expired) {
            logger->info("Removing expired ARP cache entry for IP {}.", entry.first);
        }
        return expired;
    });

    logger->info("Finished processing ARP requests and cache maintenance.");
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);
    spdlog::info("Adding ARP cache entry for IP {} with MAC {}.", ip, macToString(mac));

    entries[ip] = {ip, mac, std::chrono::steady_clock::now()};

    auto it = requests.find(ip);
    if (it != requests.end()) {
        spdlog::info("Sending queued packets for IP {}.", ip);

        for (const auto& awaitingPacket : it->second.awaitingPackets) {
            packetSender->sendPacket(awaitingPacket.packet, awaitingPacket.iface);
        }

        requests.erase(it);
    }
}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);
    auto it = entries.find(ip);

    if (it != entries.end()) {
        spdlog::info("Found ARP cache entry for IP {}: MAC {}.", ip, macToString(it->second.mac));
        return it->second.mac;
    }

    spdlog::warn("No ARP cache entry found for IP {}.", ip);
    return std::nullopt;
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);
    spdlog::info("Queueing packet for IP {} on interface {}.", ip, iface);

    auto it = requests.find(ip);

    if (it == requests.end()) {
        spdlog::info("Creating new ARP request for IP {}.", ip);
        ArpRequest newRequest{ip, std::chrono::steady_clock::now(), 0, {}};
        newRequest.awaitingPackets.emplace_back(packet, iface);
        requests[ip] = std::move(newRequest);
    } else {
        spdlog::info("Adding packet to existing ARP request for IP {}.", ip);
        it->second.awaitingPackets.emplace_back(packet, iface);
    }
}