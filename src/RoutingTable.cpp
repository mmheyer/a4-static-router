#include "RoutingTable.h"

#include <arpa/inet.h>
#include <fstream>
#include <sstream>
#include <spdlog/spdlog.h>
#include <iostream>
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
    RoutingEntry bestMatch;
    int longestPrefixMatch = -1;

    if (routingEntries.empty()) {
        return std::nullopt;
    }

    uint32_t ip_network_order = ip;

    for (const auto& entry : routingEntries) {
        uint32_t dest_ip_host_order = entry.dest;
        uint32_t mask_host_order = entry.mask;

        uint32_t network = dest_ip_host_order & mask_host_order;
        uint32_t ip_network = ip_network_order & mask_host_order;

        if (network == ip_network) {
            int prefixLength = __builtin_popcount(entry.mask);;
            
            if (prefixLength > longestPrefixMatch) {
                longestPrefixMatch = prefixLength;
                bestMatch = entry;
      
            }
        }
    }

    
    if (longestPrefixMatch != -1) {
       return bestMatch;
    }
    return std::nullopt;  // No match found
}



RoutingInterface RoutingTable::getRoutingInterface(const std::string& iface) {
    return routingInterfaces.at(iface);
}

void RoutingTable::setRoutingInterface(const std::string& iface, const mac_addr& mac, const ip_addr& ip) {
    routingInterfaces[iface] = {iface, mac, ip};
    struct in_addr ip_addr_struct;
    ip_addr_struct.s_addr = ip;
     std::cout << "Setting interface: " << iface 
              << ", IP: " << inet_ntoa(ip_addr_struct) << std::endl;
}

const std::unordered_map<std::string, RoutingInterface>& RoutingTable::getRoutingInterfaces() const
{
    return routingInterfaces;
}