#include "CLI.h"

using namespace std;

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
    cout << "--------------ShockWave----------------" << endl;
    cout << "-----------By Transpalette-------------" << endl;
    cout << "--Kick em out of your personal space---" << endl;
    cout << "***************************************" << endl;
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

    cout << "-> BSSID: AE:28:06:AD:19:70" << endl;
    cout << "-> Target: 40:b4:cd:6e:de:d5" << endl;
    cout << "Deauthenticating... (ctrl+c to stop)" << endl;

    while (true) {
        network.sendDeauth();
        usleep(1000000);
    }
}
