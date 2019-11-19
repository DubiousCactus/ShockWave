#ifndef NETWORK_H
#define NETWORK_H

#include <thread>
#include <atomic>
#include <tins/tins.h>

class Network
{
    typedef Tins::Dot11::address_type address_type;
    typedef std::set<address_type> ssids_type;

    private:
        ssids_type ssids;
        std::map<std::string, std::set<address_type>> accessPoints;
        Tins::NetworkInterface defaultIface = Tins::NetworkInterface::default_interface();
        std::string spoofingIfaceName;
        Tins::HWAddress<6> spoofedBSSID;
        std::map<Tins::IPv4Address, Tins::HWAddress<6>> targets;
        Tins::Dot11Deauthentication deauthPacket;
        Tins::RadioTap radio;
        std::thread deauthThread;
        bool apScanCallback(Tins::PDU& pdu);
        bool ipScanCallback(Tins::PDU& pdu);
        std::atomic<bool> apScanning;
        std::atomic<bool> deauthing;
        std::atomic<bool> ipScanning;
        void sendDeauth();

    public:
        Network();
        virtual ~Network();
        std::vector<std::wstring> getInterfaces();
        void setSpoofingInterface(std::string interface);
        void setBssid(const Tins::HWAddress<6> hwAddress);
        void connectAP();
        std::string getBssid();
        int getConnectedDevices(std::string iprange);
        std::map<std::string, std::set<address_type>> getAccessPoints();
        void scanDevices(Tins::PacketSender& sender, std::string iprange);
        void startDeauth();
        void stopDeauth();

    protected:

};

#endif // NETWORK_H
