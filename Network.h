#ifndef NETWORK_H
#define NETWORK_H

#include <tins/tins.h>

class Network
{
    typedef Tins::Dot11::address_type address_type;
    typedef std::set<address_type> ssids_type;

    private:
        ssids_type ssids;
        std::map<std::string, address_type> accessPoints;
        Tins::NetworkInterface iface;
        Tins::PacketSender sender;
        Tins::HWAddress<6> bssid;
        Tins::HWAddress<6> target;
        Tins::Dot11Deauthentication deauthPacket;
        Tins::RadioTap radio;
        bool scanCallback(Tins::PDU& pdu);

    public:
        Network();
        virtual ~Network();
        void sendDeauth();
        std::vector<std::wstring> getInterfaces();
        void setInterface(std::string interface);
        void setBssid(const std::string hwAddress);
        std::string getBssid();
        std::vector<std::string> getConnectedDevices();
        std::map<std::string, address_type> getAccessPoints();

    protected:

};

#endif // NETWORK_H