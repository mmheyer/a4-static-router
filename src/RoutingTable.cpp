#include "RoutingTable.h"

#include <arpa/inet.h>
#include <fstream>
#include <sstream>
#include <spdlog/spdlog.h>

RoutingTable::RoutingTable(const std::filesystem::path& routingTablePath) {
    if (!std::filesystem::exists(routingTablePath)) {
        throw std::runtime_error("Routing table file does not exist");
    }

    std::ifstream file(routingTablePath);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open routing table file");
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) {
            continue;
        }

        std::istringstream iss(line);
        std::string dest, gateway, mask, iface;
        iss >> dest >> gateway >> mask >> iface;

        uint32_t dest_ip, gateway_ip, subnet_mask;

        if (inet_pton(AF_INET, dest.c_str(), &dest_ip) != 1 ||
            inet_pton(AF_INET, gateway.c_str(), &gateway_ip) != 1 ||
            inet_pton(AF_INET, mask.c_str(), &subnet_mask) != 1) {
            spdlog::error("Invalid IP address format in routing table file: {}", line);
            throw std::runtime_error("Invalid IP address format in routing table file");
            }

        routingEntries.push_back({dest_ip, gateway_ip, subnet_mask, iface});
    }
}
// Called when our router needs to determine how to forward an IP packet
std::optional<RoutingEntry> RoutingTable::getRoutingEntry(ip_addr ip) {
    uint32_t bestMatchLength = 0;  // len of longest matching prefix, initially 0
    std::optional<RoutingEntry> bestEntry = std::nullopt; // initially, no match 
    uint32_t bestCloseness = UINT32_MAX; // used for ties

    // convert input IP using host to network long
    uint32_t ipNetworkOrder = htonl(ip);

    // for all entries in the routing table
    for (const auto& entry : routingEntries) {
        // apply the subnet mask to destination IP and input ip
        uint32_t maskedDest = entry.dest & entry.mask; // bitwise & desination IP and mask
        uint32_t maskedIP = ipNetworkOrder & entry.mask; // bitwise & input ip and mask

        // if maskedDest == maskedIP, the input ip falls within the entry's subnet mask
        // therefore, the input ip belongs to the same network as the routing entry
        if (maskedDest == maskedIP) {
            // count num of bits set to 1 (prefix length) in the subnet mask
            uint32_t maskLength = __builtin_popcount(ntohl(entry.mask)); // convert mask using network to host long for popcount

            // resolve ties by prefering the entry where the input IP is closer to the entry's destination
            uint32_t closeness = ntohl(ipNetworkOrder ^ maskedDest); // smaller val => closer match

            // update best match if:
            // 1. prefix length is longer OR
            // 2. prefix length is the same, but the closeness is smaller
            if (maskLength > bestMatchLength || (maskLength == bestMatchLength && closeness < bestCloseness)) {
                bestMatchLength = maskLength;
                bestCloseness = closeness;
                bestEntry = entry;
            }
        }
    }

    // return std::nullopt if no match, otherwise return longest prefix match
    return bestEntry;
}

// Called when our router needs to determine how to forward an IP packet
// std::optional<RoutingEntry> RoutingTable::getRoutingEntry(ip_addr ip) {

//     uint32_t bestMatchLength = 0; // len of longest matching prefix, initially 0
//     std::optional<RoutingEntry> bestEntry = std::nullopt; // initially, no match 

//     // for all entries in the routing table
//     for (const auto& entry : routingEntries) {
//         // apply the subnet mask to destination IP and input ip
//         uint32_t maskedDest = entry.dest & entry.mask; // bitwise & desination IP and mask
//         uint32_t maskedIP = ip & entry.mask; // bitwise & input ip and mask

//         // if maskedDest == maskedIP, the input ip falls within the entry's subnet mask
//         // therefore, the input ip belongs to the same network as the routing entry
//         if (maskedDest == maskedIP) {
//             // count num of bits set to 1 (prefix length) in the subnet mask
//             uint32_t maskLength = __builtin_popcount(entry.mask);
//             // update best match if we found an entry with a longer prefix
//             if (maskLength > bestMatchLength) {
//                 bestMatchLength = maskLength;
//                 bestEntry = entry;
//             }
//         }
//     }
//     // return std::nullopt if no match, otherwise return longest prefix match
//     return bestEntry;
// }

RoutingInterface RoutingTable::getRoutingInterface(const std::string& iface) {
    return routingInterfaces.at(iface);
}

void RoutingTable::setRoutingInterface(const std::string& iface, const mac_addr& mac, const ip_addr& ip) {
    routingInterfaces[iface] = {iface, mac, ip};
}

const std::unordered_map<std::string, RoutingInterface>& RoutingTable::getRoutingInterfaces() const
{
    return routingInterfaces;
}
