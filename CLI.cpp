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
    cout << "***************************************" << endl << endl;
}

void CLI::listConnectedHosts() {
    vector<string> hosts = network.getConnectedDevices();

    for (const string& host : hosts) {
        cout << " -> " << host << endl;
    }
}

void CLI::listInterfaces() {
    interfaces = network.getInterfaces();

    int i = 0;
    for (const wstring& iface : interfaces) {
        wcout << ++i << ". " << iface << endl;
    }
}

void CLI::listAccessPoints() {
    aps = network.getAccessPoints();
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

void CLI::chooseAccessPoint(int no) {
    int i = 1;
    for(map<string, address_type>::iterator iterator = aps.begin(); iterator != aps.end(); iterator++, i++) {
        cout << iterator->second.to_string() <<endl;
        if(i == no) {
            network.setBssid(iterator->second.to_string());
            break;
        }
    }
}

void CLI::showAction() {
    switch(state) {
        case CHOOSEIF:
            listInterfaces();
            int interfaceNo;
            cout << endl << endl << "Interface: ";
            cin >> interfaceNo;
            chooseInterface(interfaceNo);
            state = LISTAPS;
            break;
        case LISTAPS:
            listAccessPoints();
            int ap;
            cout << endl << endl << "Access point: ";
            cin >> ap;
            chooseAccessPoint(ap);
            state = LISTHOSTS;
        case LISTHOSTS:
            listConnectedHosts();
            state = WHITELIST;
            break;
        case WHITELIST:

            state = ATTACK;
            break;
        case ATTACK:
            attack();
            break;
    }
}

void CLI::showMenu() {
    if(state != WHITELIST)
        system("clear");
    showHeader();
    showAction();
}

void CLI::attack() {

    cout << "-> BSSID: " << network.getBssid() << endl;
    cout << "-> Target: 40:b4:cd:6e:de:d5" << endl;
    cout << "Deauthenticating... (ctrl + c to stop)" << endl;

    while (true) {
        network.sendDeauth();
        usleep(1000000);
    }
}