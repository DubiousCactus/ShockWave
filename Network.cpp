#include <boost/algorithm/string.hpp>
#include <codecvt>
#include <iostream>
#include <thread>
#include <tins/icmp.h>
#include <zconf.h>

#include "Network.h"

using namespace Tins;

Network::Network()
{
    iface = NetworkInterface::default_interface();
    deauthPacket = Dot11Deauthentication(target, bssid); // Set target / sender
    deauthPacket.addr3(bssid);                           // Set the BSSID
    deauthPacket.reason_code(0x0007);                    // From airplay-ng
    radio = RadioTap() / deauthPacket;
}

Network::~Network() {}

void
Network::sendDeauth()
{
    // sender.send(radio, ifaceName);
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
    int delimiter_pos = iprange.find(":");
    std::string from = iprange.substr(0, delimiter_pos);
    std::string to =
      iprange.substr(delimiter_pos + 1, iprange.length() - delimiter_pos);
    // TODO: Validate the range
    Tins::IPv4Range networkRange = Tins::IPv4Range::from_mask(from, to);
    NetworkInterface::Info infoScanner = iface.info();
    for (const auto& target : networkRange) {
        IP ping = IP(target, infoScanner.ip_addr) / ICMP();
        sender.send(ping, iface);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
    SnifferConfiguration config;
    config.set_promisc_mode(false);
    config.set_filter("ip proto \\icmp and not src host " +
                      iface.addresses().ip_addr.to_string());
    Sniffer sniffer(iface.name(), config);

    PacketSender sender;
    auto handler = bind(&Network::ipScanCallback, this, std::placeholders::_1);
    ipScanning = true;
    std::thread sniff_thread([&]() { sniffer.sniff_loop(handler); });
    std::cout << "[*] Running IP scan..." << std::endl;
    scanDevices(sender, iprange);
    sniff_thread.join();
}

std::map<std::string, std::set<Dot11::address_type>>
Network::getAccessPoints()
{
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("type mgt subtype beacon");
    config.set_rfmon(true);
    Sniffer sniffer(iface.name(), config);

    std::thread scanThread(&Network::stopScan, &scanning);
    scanThread.detach();

    sniffer.sniff_loop(make_sniffer_handler(this, &Network::scanCallback));

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
Network::setInterface(std::string interface)
{
    // ifaceName = interface;
}

void
Network::setBssid(const std::string hwAddress)
{
    bssid = HWAddress<6>(hwAddress);
}

std::string
Network::getBssid()
{
    return bssid.to_string();
}
