#include "ArpCache.h"

#include <chrono>
#include <thread>
#include <cstring>
#include <spdlog/spdlog.h>
#include <iostream>

#include "protocol.h"
#include "utils.h"

ArpCache::ArpCache(std::chrono::milliseconds timeout, std::shared_ptr<IPacketSender> packetSender, std::shared_ptr<IRoutingTable> routingTable)
: timeout(timeout)
, packetSender(std::move(packetSender))
, routingTable(std::move(routingTable))
, icmpSender(std::make_shared<ICMPSender>(this->packetSender))
, arpSender(std::make_shared<ARPSender>(this->packetSender)) {
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);
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

    auto now = std::chrono::steady_clock::now();
    std::vector<uint32_t> requestsToRemove; // Collect IPs to erase after processing

    for (auto& [ip, req] : requests) {
        std::cout << "Processing ARP request for IP: " << ip << ", timesSent: " << req.timesSent
                  << ", lastSent: " << std::chrono::duration_cast<std::chrono::milliseconds>(now - req.lastSent).count()
                  << " ms ago.\n";
        // Check if a request has timed out (sent 7 times with no reply)
        if (req.timesSent >= 7) {
            std::cout << "Max retries reached for IP " << ip << ". Sending ICMP Destination Host Unreachable.\n";
            spdlog::warn("ARP request for IP {} failed after {} attempts. Sending ICMP Destination Host Unreachable.", ip, req.timesSent);

            // Notify all awaiting packets with ICMP Destination Host Unreachable
            for (auto& awaitingPacket : req.awaitingPackets) {
                
                auto ifaceInfo = routingTable->getRoutingInterface(awaitingPacket.iface);
                sr_ethernet_hdr_t *ethernet_hdr = reinterpret_cast<sr_ethernet_hdr_t *>(awaitingPacket.packet.data());
                icmpSender->sendDestinationUnreachable(
                    awaitingPacket.packet,
                    ifaceInfo.mac,
                    ifaceInfo.ip,
                    extractSourceMAC(ethernet_hdr),
                    extractSourceIP(awaitingPacket.packet),
                    awaitingPacket.iface,
                    ICMPSender::DestinationUnreachableCode::HOST_UNREACHABLE
                );


// Debugging outputs
                std::cout << "[DEBUG] Packet Data: ";
                for (const auto& byte : awaitingPacket.packet) {
                    std::cout << std::hex << static_cast<int>(byte) << " ";
                }
                std::cout << std::endl;

                std::cout << "[DEBUG] Interface MAC Address: " << macToString(ifaceInfo.mac) << std::endl;
                std::cout << "[DEBUG] Interface IP Address: " << ifaceInfo.ip << std::endl;

                mac_addr srcMac = extractSourceMAC(ethernet_hdr);
                std::cout << "[DEBUG] Source MAC Address: " << macToString(srcMac) << std::endl;

                uint32_t srcIp = extractSourceIP(awaitingPacket.packet);
                std::cout << "[DEBUG] Source IP Address: " << srcIp << std::endl;

                std::cout << "[DEBUG] Interface Name: " << awaitingPacket.iface << std::endl;
                std::cout << "[DEBUG] ICMP Code: " << static_cast<int>(ICMPSender::DestinationUnreachableCode::HOST_UNREACHABLE) << std::endl;                
                 std::cout << "Sent ICMP Destination Host Unreachable for packet on interface: " << awaitingPacket.iface << "\n";

            }

            requestsToRemove.push_back(ip);
        } else if (now - req.lastSent >= std::chrono::seconds(1)) {
            // Retry ARP request if more than 1 second has passed since the last attempt
            auto route = routingTable->getRoutingInterface(req.awaitingPackets.front().iface);
            spdlog::info("Retrying ARP request for IP {} on interface {}. Attempt #{}.", ip, route.name, req.timesSent + 1);

            // arpSender->sendArpRequest(ip, route.name); // Schedule ARP request
            arpSender->sendArpRequest(ip, route.ip, route.mac.data(), route.name); // Schedule ARP request
            req.lastSent = now;
            req.timesSent++;
        }
    }

    // Remove expired requests
    for (uint32_t ip : requestsToRemove) {
        requests.erase(ip);
    }

    // Cleanup expired ARP cache entries
    auto entryIt = entries.begin();
    while (entryIt != entries.end()) {
        if (now - entryIt->second.timeAdded > timeout) {
            spdlog::info("ARP cache entry for IP {} expired.", entryIt->first);
            entryIt = entries.erase(entryIt);
        } else {
            ++entryIt;
        }
    }
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

    // If there is no existing ARP request for this IP, create a new one
    if (it == requests.end()) {
        spdlog::info("Creating new ARP request queue for IP {}.", ip);
        ArpRequest newRequest{ip, std::chrono::steady_clock::now(), 0, {}};
        newRequest.awaitingPackets.emplace_back(packet, iface);
        requests[ip] = std::move(newRequest);
    } else {
        spdlog::info("Adding packet to existing ARP request queue for IP {}.", ip);
        it->second.awaitingPackets.emplace_back(packet, iface);
    }

    if (shouldSendArpRequest(ip)) {
        arpSender->sendArpRequest(
            ip,
            routingTable->getRoutingInterface(iface).ip,
            routingTable->getRoutingInterface(iface).mac.data(),
            iface
        );
        std::cout << "Sending ARP request for IP: " << routingTable->getRoutingInterface(iface).ip << " via interface: " << iface << ".\n";

    }
}

bool ArpCache::shouldSendArpRequest(uint32_t ip) {
    std::unique_lock lock(mutex);

    auto now = std::chrono::steady_clock::now();

    // Check if an ARP request for the given IP already exists
    auto it = requests.find(ip);
    if (it != requests.end()) {
        ArpRequest& req = it->second;

        // Check the last sent time of the request
        if (now - req.lastSent < std::chrono::seconds(1)) {
            spdlog::info("Skipping ARP request for IP {} as one was sent recently.", ip);
            return false; // ARP request was sent recently
        }

        // Update the request's lastSent time to now
        req.lastSent = now;
        req.timesSent++; // Increment the count of ARP requests sent
        spdlog::info("Allowing ARP request for IP {} after cooldown.", ip);
        return true;
    }

    // No ARP request exists for this IP, create a new request
    ArpRequest newRequest{ip, now, 1, {}};
    requests[ip] = std::move(newRequest);

    spdlog::info("Allowing ARP request for IP {} as no prior request exists.", ip);
    return true;
}
