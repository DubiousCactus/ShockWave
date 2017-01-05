#ifndef NETWORK_H
#define NETWORK_H

#include <tins/tins.h>

class Network
{
    public:
        Network();
        virtual ~Network();
        void sendDeauth();
    protected:
    private:
        Tins::PacketSender sender;
        Tins::HWAddress<6> bssid;
        Tins::HWAddress<6> target;
        Tins::Dot11Deauthentication deauthPacket;
        Tins::RadioTap radio;
};

#endif // NETWORK_H
