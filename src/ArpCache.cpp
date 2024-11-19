#include "ArpCache.h"

#include <thread>
#include <cstring>
#include <spdlog/spdlog.h>

#include "protocol.h"
#include "utils.h"


ArpCache::ArpCache(std::chrono::milliseconds timeout, std::shared_ptr<IPacketSender> packetSender, std::shared_ptr<IRoutingTable> routingTable)
: timeout(timeout)
, packetSender(std::move(packetSender))
, routingTable(std::move(routingTable)) {
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);
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
    // TODO: Your code here

    // get the current time
    auto now = std::chrono::steady_clock::now();

    // process ARP requests
    for (auto reqIt = requests.begin(); reqIt != requests.end();) {
        ArpRequest& req = reqIt->second;

        // if the last request was sent more than a second ago
        if (now - req.lastSent > std::chrono::seconds(1)) {
            // if the request has been sent more than 7 times
            if (req.timesSent >= 7) {
                // send ICMP "Destination Host Unreachable" to each packet's source
                for (const auto& awaitingPacket : req.awaitingPackets) {
                    // TODO: finish writing this function
                }
            }
         }
    }

    // TODO: Your code should end here

    // Remove entries that have been in the cache for too long
    std::erase_if(entries, [this](const auto& entry) {
        return std::chrono::steady_clock::now() - entry.second.timeAdded >= timeout;
    });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);

    // add the IP-MAC mapping to the ARP cache
    entries[ip] = ArpEntry(ip, mac);

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
