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
        std::string ifaceName;
        Tins::PacketSender sender;
        Tins::HWAddress<6> bssid;
        Tins::HWAddress<6> target;
        Tins::IPv4Range networkRange = Tins::IPv4Range::from_mask("10.10.10.2", "10.10.10.255");
        Tins::Dot11Deauthentication deauthPacket;
        Tins::RadioTap radio;
        bool scanCallback(Tins::PDU& pdu);
        bool scanning = true;
        static void stopScan(bool *scanning);

    public:
        Network();
        virtual ~Network();
        void sendDeauth();
        std::vector<std::wstring> getInterfaces();
        void setInterface(std::string interface);
        void setBssid(const std::string hwAddress);
        std::string getBssid();
        std::vector<std::string> getConnectedDevices();
        std::map<std::string, std::set<address_type>> getAccessPoints();

    protected:

};

#endif // NETWORK_H