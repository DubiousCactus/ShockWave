#ifndef NETWORK_H
#define NETWORK_H

#include <tins/tins.h>

class Network
{
    typedef Tins::Dot11::address_type address_type;
    typedef std::set<address_type> ssids_type;

    private:
        ssids_type ssids;
        std::map<std::string, std::set<address_type>> accessPoints;
        Tins::NetworkInterface iface;
        //Tins::PacketSender sender;
        Tins::HWAddress<6> bssid;
        Tins::HWAddress<6> target;
        std::map<Tins::IPv4Address, Tins::HWAddress<6>> targets;
        //Tins::IPv4Range networkRange;
        Tins::Dot11Deauthentication deauthPacket;
        Tins::RadioTap radio;
        bool scanCallback(Tins::PDU& pdu);
        bool ipScanCallback(Tins::PDU& pdu);
        bool scanning = true;
        bool ipScanning = false;
        static void stopScan(bool *scanning);

    public:
        Network();
        virtual ~Network();
        void sendDeauth();
        std::vector<std::wstring> getInterfaces();
        void setInterface(std::string interface);
        void setBssid(const std::string hwAddress);
        void connectAP();
        std::string getBssid();
        void getConnectedDevices(std::string iprange);
        std::map<std::string, std::set<address_type>> getAccessPoints();
        void scanDevices(Tins::PacketSender& sender, std::string iprange);

    protected:

};

#endif // NETWORK_H
