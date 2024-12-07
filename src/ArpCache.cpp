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

void ArpCache::processPending() {
    std::unique_lock lock(mutex);

    auto now = std::chrono::steady_clock::now();
    std::vector<uint32_t> pendingRequestsToRemove;  // List of IPs whose requests have been processed (timeout or answered)

    // Iterate through all the requests and process them
    for (auto& [ip, req] : requests) {
        // Check if the request has timed out
        auto timeSinceLastSent = std::chrono::duration_cast<std::chrono::seconds>(now - req.lastSent);

        if (timeSinceLastSent >= std::chrono::seconds(1)) {
            // Retry sending ARP request if the last one was sent more than a second ago
            if (req.timesSent < 7) {  // Max retry attempts
                auto route = routingTable->getRoutingInterface(req.awaitingPackets.front().iface);
                spdlog::info("Retrying ARP request for IP {} on interface {}. Attempt #{}.", ip, route.name, req.timesSent + 1);
                arpSender->sendArpRequest(ip, route.ip, route.mac.data(), route.name);
                req.lastSent = now;
                req.timesSent++;
            } else {
                // If retries are exhausted, mark for removal and send ICMP Destination Unreachable
                spdlog::warn("Max retry limit reached for IP {}. Sending ICMP Destination Host Unreachable.", ip);
                for (auto& awaitingPacket : req.awaitingPackets) {
                    auto ifaceInfo = routingTable->getRoutingInterface(awaitingPacket.iface);
                    sr_ethernet_hdr_t* ethernet_hdr = reinterpret_cast<sr_ethernet_hdr_t*>(awaitingPacket.packet.data());
                    icmpSender->sendDestinationUnreachable(
                        awaitingPacket.packet,
                        ifaceInfo.mac,
                        ifaceInfo.ip,
                        extractSourceMAC(ethernet_hdr),
                        extractSourceIP(awaitingPacket.packet),
                        awaitingPacket.iface,
                        ICMPSender::DestinationUnreachableCode::HOST_UNREACHABLE
                    );
                }
                pendingRequestsToRemove.push_back(ip); // Mark IP for removal due to timeout
            }
        }
    }

    // Remove requests that are either successfully resolved or have timed out
    for (uint32_t ip : pendingRequestsToRemove) {
        requests.erase(ip);
    }
}

bool ArpCache::hasRequest(uint32_t ip) {
    std::lock_guard<std::mutex> lock(mutex); // Ensure thread safety

    // Check if the IP exists in the requests map
    return requests.find(ip) != requests.end();
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

            // remove the request
            requests.erase(ip);
            spdlog::debug("Removed request for IP {} due to destination unreachable.");
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

        for (auto& awaitingPacket : it->second.awaitingPackets) {
            spdlog::info("Sending packet out of interface {}", awaitingPacket.iface);
            
            // Extract packet data and interface
            auto& packet = awaitingPacket.packet;
            const auto& queuedIface = awaitingPacket.iface;

            // Modify the Ethernet header
            auto* queuedEthHeader = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
            std::memcpy(queuedEthHeader->ether_dhost, mac.data(), ETHER_ADDR_LEN);
            std::memcpy(queuedEthHeader->ether_shost, routingTable->getRoutingInterface(queuedIface).mac.data(), ETHER_ADDR_LEN);

            // Send the packet
            packetSender->sendPacket(packet, queuedIface);
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

// Helper function to convert MAC address to a string
std::string macArrayToString(const uint8_t mac[ETHER_ADDR_LEN]) {
    std::ostringstream macStream;
    for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
        macStream << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(mac[i]);
        if (i < ETHER_ADDR_LEN - 1) {
            macStream << ":";
        }
    }
    return macStream.str();
}

void logAwaitingPackets(const std::list<AwaitingPacket>& awaitingPackets) {
    for (const auto& awaitingPacket : awaitingPackets) {
        const auto& packet = awaitingPacket.packet;
        const auto& iface = awaitingPacket.iface;

        // Log the packet size and associated interface
        spdlog::info("Packet on interface {}: Size = {} bytes", iface, packet.size());

        // Ensure the packet is large enough to contain an Ethernet header
        if (packet.size() >= sizeof(sr_ethernet_hdr_t)) {
            const auto* ethHeader = reinterpret_cast<const sr_ethernet_hdr_t*>(packet.data());

            // Log Ethernet header details
            spdlog::info("  Ethernet Header:");
            spdlog::info("    Destination MAC: {}", macArrayToString(ethHeader->ether_dhost));
            spdlog::info("    Source MAC: {}", macArrayToString(ethHeader->ether_shost));
            spdlog::info("    EtherType: 0x{:04x}", ntohs(ethHeader->ether_type));
        } else {
            spdlog::warn("  Packet is too small to contain an Ethernet header.");
        }
    }
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);
    spdlog::info("Queueing packet for IP {} on interface {}.", ip, iface);
    print_addr_ip_int(ip);

    auto it = requests.find(ip);

    // If there is no existing ARP request for this IP, create a new one
    if (it == requests.end()) {
        spdlog::info("Creating new ARP request queue for IP {}.", ip);
        ArpRequest newRequest{ip, std::chrono::steady_clock::now(), 0, {}};
        newRequest.awaitingPackets.emplace_back(packet, iface);
        requests[ip] = std::move(newRequest);
        spdlog::debug("There are {} requests after adding a request.", requests.size());
        logAwaitingPackets(requests[ip].awaitingPackets);
    } else {
        spdlog::info("Adding packet to existing ARP request queue for IP {}.", ip);
        it->second.awaitingPackets.emplace_back(packet, iface);
        spdlog::debug("There are {} requests after adding a request.", requests.size());
        logAwaitingPackets(it->second.awaitingPackets);
    }

    std::cout << " * " << std::endl;
    lock.unlock();

    // if (shouldSendArpRequest(ip)) {
    //     std::cout << " ** " << std::endl;
       
    //     // Retrieve routing interface information
    //     auto routingInterface = routingTable->getRoutingInterface(iface);
    //     uint32_t senderIP = routingInterface.ip;
    //     const uint8_t* senderMac = routingInterface.mac.data();
    //     std::cout << "[arpcache queue] Routing Interface - Sender IP: " 
    //       << senderIP << ", Sender MAC: " << routingInterface.mac.data() << std::endl;
    //     // Build an ARP request packet
    //     std::vector<uint8_t> arpPacket(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

    //     // Ethernet header
    //     auto* ethHeader = reinterpret_cast<sr_ethernet_hdr_t*>(arpPacket.data());
    //     std::fill(std::begin(ethHeader->ether_dhost), std::end(ethHeader->ether_dhost), 0xFF); // Broadcast MAC address
    //     std::memcpy(ethHeader->ether_shost, senderMac, ETHER_ADDR_LEN); // Sender's MAC address
    //     ethHeader->ether_type = htons(ethertype_arp);

    //     std::cout << "[arpcache queue] Ethernet Header - Broadcast MAC, Sender MAC: ";
    //     for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
    //         std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ethHeader->ether_shost[i]);
    //     }
    //     std::cout << ", EtherType: " << std::hex << ntohs(ethHeader->ether_type) << std::dec << std::endl;


    //     // ARP header
    //     auto* arpHeader = reinterpret_cast<sr_arp_hdr_t*>(arpPacket.data() + sizeof(sr_ethernet_hdr_t));
    //     arpHeader->ar_hrd = htons(arp_hrd_ethernet); // Hardware type: Ethernet
    //     arpHeader->ar_pro = htons(ethertype_ip);     // Protocol type: IPv4
    //     arpHeader->ar_hln = ETHER_ADDR_LEN;         // Hardware address length
    //     arpHeader->ar_pln = sizeof(uint32_t);       // Protocol address length
    //     arpHeader->ar_op = htons(arp_op_request);   // ARP operation: request

    //     // Sender's hardware and protocol addresses
    //     std::memcpy(arpHeader->ar_sha, senderMac, ETHER_ADDR_LEN);
    //     arpHeader->ar_sip = senderIP;

    //     // Target's hardware address is empty for a request
    //     std::fill(std::begin(arpHeader->ar_tha), std::end(arpHeader->ar_tha), 0x00);
    //     arpHeader->ar_tip = ip;

    //     std::cout << "[arpcache queue] ARP Header - Sender MAC: ";
    //     for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
    //         std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(arpHeader->ar_sha[i]);
    //     }
    //     std::cout << ", Sender IP: " << std::dec << senderIP 
    //             << ", Target IP: " << ip << std::endl;

    //     // Log packet contents
    //     spdlog::debug("ARP Request: Sender IP: {}, Target IP: {}", senderIP, ip);
    //     std::cout << "[arpcache queue] ARP Packet ready, sending to interface: " << iface << std::endl;

    //     // Send the ARP request directly
    //     packetSender->sendPacket(arpPacket, iface);

    //     std::cout << "ARP Request sent for IP: " << ip << " from sender IP: " << senderIP << " via interface: " << iface << ".\n";
    // }
    // std::cout << " * " << std::endl;

}


// bool ArpCache::shouldSendArpRequest(uint32_t ip) {
//     std::cout << "[SHOULD SEND ARP REQUEST]" << std::endl;

//     // Lock the mutex to ensure thread safety when checking or modifying shared state.
//     std::unique_lock lock(mutex);
//     std::cout << "[SHOULD SEND ARP REQUEST] post lock" << std::endl;

//     auto now = std::chrono::steady_clock::now();

//     // Check if an ARP request for the given IP already exists
//     auto it = requests.find(ip);
//     if (it != requests.end()) {
//         ArpRequest& req = it->second;

//         // Calculate time difference and log it
//         auto timeDiff = std::chrono::duration_cast<std::chrono::seconds>(now - req.lastSent);
//         std::cout << "[SHOULD SEND ARP REQUEST] Time since last ARP request: " 
//                   << timeDiff.count() << " seconds." << std::endl;

//         // Check if the ARP request was sent recently
//         if (timeDiff < std::chrono::seconds(1) && timeDiff.count() != 0) {
//             std::cout << "FALSE" << std::endl;
//             spdlog::info("Skipping ARP request for IP {} as one was sent recently.", ip);
//             lock.unlock();
//             return false; // ARP request was sent recently
//         }

//         // Update the request's lastSent time to now
//         req.lastSent = now;
//         req.timesSent++; // Increment the count of ARP requests sent
//         spdlog::info("Allowing ARP request for IP {} after cooldown.", ip);
//         std::cout << "TRUE" << std::endl;
//         lock.unlock();
//         return true;
//     }

//     // If no ARP request exists for this IP, create a new one
//     std::cout << "No ARP request exists for IP, creating new one." << std::endl;
//     ArpRequest newRequest{ip, now, 1, {}};
//     requests[ip] = std::move(newRequest);
//     spdlog::debug("There are {} requests after adding the request.", requests.size());

//     spdlog::info("Allowing ARP request for IP {} as no prior request exists.", ip);
//     std::cout << "TRUE (new request)" << std::endl;
//     lock.unlock();
//     return true;
// }

std::optional<std::__cxx11::list<AwaitingPacket>> ArpCache::getQueuedPackets(uint32_t ip) {
    std::unique_lock lock(mutex); // Ensure thread safety

    spdlog::debug("There are {} requests.", requests.size());

    for (auto& request : requests) {
        spdlog::debug("There is a request for IP:");
        print_addr_ip_int(request.second.ip);
    }

    spdlog::debug("Looking for queued packets for IP:");
    print_addr_ip_int(ip);

    auto it = requests.find(ip);
    if (it != requests.end()) {
        return it->second.awaitingPackets;
    }

    spdlog::warn("No queued packets found for IP:");
    print_addr_ip_int(ip);
    return std::nullopt;
}

void ArpCache::removeRequest(uint32_t ip) {
    std::unique_lock lock(mutex); // Ensure thread safety

    auto it = requests.find(ip);
    if (it != requests.end()) {
        // Remove the ARP request entry
        spdlog::info("Removing ARP request for IP:");
        print_addr_ip_int(ip);
        requests.erase(it);
    } else {
        spdlog::warn("Attempted to remove non-existent ARP request for IP:");
        print_addr_ip_int(ip);
    }
}
