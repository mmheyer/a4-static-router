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
                handleDestHostUnreachable(req);

                // Erase the ARP request after sending ICMP errors
                reqIt = requests.erase(reqIt);
                continue;
            } else {
                retryArpRequest(req);
            }
        }
        ++reqIt;
    }

    // Remove expired ARP cache entries
    std::erase_if(entries, [this, now, logger](const auto& entry) {
        bool expired = now - entry.second.timeAdded >= timeout;
        if (expired) {
            logger->info("Removing expired ARP cache entry for IP {}.", entry.first);
            // If entry was part of an ongoing ARP request
            auto reqIt = requests.find(entry.first);
            if (reqIt != requests.end()) {
                spdlog::info("ARP cache entry for IP {} expired while waiting for ARP response. Sending ICMP Host Unreachable.", entry.first);
                handleDestHostUnreachable(reqIt->second);

                // Erase the associated ARP request
                requests.erase(reqIt);
            }
        }
        return expired;
    });

    // logger->info("Finished processing ARP requests and cache maintenance.");
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
}

void ArpCache::handleDestHostUnreachable(ArpRequest& req) {
    spdlog::warn("ARP request for IP {} failed after {} attempts. Sending ICMP Host Unreachable.", req.ip, req.timesSent);

    // Send ICMP Host Unreachable for each awaiting packet
    for (const auto& awaitingPacket : req.awaitingPackets) {
        try {
            // Extract source IP and MAC from the original packet
            uint32_t sourceIP = extractSourceIP(awaitingPacket.packet);
            mac_addr sourceMAC = extractSourceMAC(awaitingPacket.packet);

            // Get routing interface for the source IP
            auto route = routingTable->getRoutingEntry(sourceIP);
            if (!route) {
                spdlog::error("No routing entry found for source IP {}.", sourceIP);
                continue;
            }

            // Get routing interface details
            auto iface = routingTable->getRoutingInterface(route->iface);
            uint32_t ifaceIP = iface.ip;
            mac_addr ifaceMAC = iface.mac;

            // Extract destination IP and pass along awaitingPacket.iface
            uint32_t destIP = extractDestinationIP(awaitingPacket.packet);
            std::cout << "going to dest unreachable for arp cache" << std::endl;
            // Send ICMP Destination Host Unreachable
            icmpSender->sendDestinationUnreachable(
                awaitingPacket.packet, ifaceMAC, ifaceIP, sourceMAC, sourceIP, awaitingPacket.iface,
                ICMPSender::DestinationUnreachableCode::HOST_UNREACHABLE);
        } catch (const std::exception& e) {
            spdlog::error("Error while sending ICMP Host Unreachable: {}", e.what());
        }
    }
}

void ArpCache::retryArpRequest(ArpRequest& req) {
    spdlog::info("Retrying ARP request for IP {} (Attempt {}).", req.ip, req.timesSent + 1);

    auto route = routingTable->getRoutingEntry(req.ip);
    if (!route) {
        spdlog::error("No route found for target IP {}.", req.ip);
        return;
    }

    auto iface = routingTable->getRoutingInterface(route->iface);
    arpSender->sendArpRequest(req.ip, iface.ip, iface.mac.data(), iface.name);

    req.lastSent = std::chrono::steady_clock::now();
    req.timesSent++;
}

void ArpCache::sendArpRequest(uint32_t targetIP, const std::string& iface) {
    std::unique_lock lock(mutex);

    auto routingInterface = routingTable->getRoutingInterface(iface);

    // Construct an ARP request packet
    std::vector<uint8_t> packet(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

    // Ethernet header
    auto* ethHeader = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    std::memcpy(ethHeader->ether_shost, routingInterface.mac.data(), ETHER_ADDR_LEN);
    std::fill(std::begin(ethHeader->ether_dhost), std::end(ethHeader->ether_dhost), 0xFF); // Broadcast
    ethHeader->ether_type = htons(ethertype_arp);

    // ARP header
    auto* arpHeader = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    arpHeader->ar_hrd = htons(arp_hrd_ethernet);
    arpHeader->ar_pro = htons(ethertype_ip);
    arpHeader->ar_hln = ETHER_ADDR_LEN;
    arpHeader->ar_pln = 4;
    arpHeader->ar_op = htons(arp_op_request);
    std::memcpy(arpHeader->ar_sha, routingInterface.mac.data(), ETHER_ADDR_LEN);
    arpHeader->ar_sip = htonl(routingInterface.ip);
    std::fill(std::begin(arpHeader->ar_tha), std::end(arpHeader->ar_tha), 0); // Target MAC unknown
    arpHeader->ar_tip = htonl(targetIP);

    // Send the packet
    packetSender->sendPacket(packet, iface);

    spdlog::info("Sent ARP request for IP {} on interface {}.", fmt::format("{:08x}", targetIP), iface);
}