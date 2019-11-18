#include "CLI.h"

CLI::CLI()
{
    state = LISTHOSTS;
}

CLI::~CLI()
{
    // dtor
}

void
CLI::mainLoop()
{
    while (true) {
        showMenu();
        usleep(100000);
    }
}

void
CLI::showHeader()
{
    std::cout << "--------------ShockWave----------------" << std::endl;
    std::cout << "-----------By Transpalette-------------" << std::endl;
    std::cout << "--Kick 'em out of your personal space--" << std::endl;
    std::cout << "***************************************" << std::endl
              << std::endl;
}

void
CLI::listConnectedHosts()
{
    std::string iprange;
    std::cout << "Enter the IP range to scan (<base_address>/<int_mask>): ";
    // std::cin >> iprange;
    // TODO: Validate with a regex
    iprange = "192.168.31.0/24";
    std::cout << iprange << std::endl;
    network.getConnectedDevices(iprange);
    std::cout << "[*] Done! ";
    do {
        std::cout << "Press enter to proceed...";
    } while (std::cin.get() != '\n');
}

void
CLI::listInterfaces()
{
    interfaces = network.getInterfaces();
    int i = 0;
    for (const std::wstring& iface : interfaces) {
        std::wcout << ++i << ". " << iface << std::endl;
    }
}

void
CLI::listAccessPoints()
{
    std::cout << "[*] Scanning access points..." << std::endl;
    aps = network.getAccessPoints();
    std::cout << std::endl << std::endl;
    int i = 0;
    for (const std::pair<std::string, std::set<address_type>>& pair : aps) {
        if (pair.first == "") {
            aps.erase(pair.first);
            continue;
        }
        std::cout << i++ << ". " << pair.first << " -> [";
        for (std::set<address_type>::iterator it = pair.second.begin();
             it != pair.second.end();
             it++) {
            std::cout << (*it).to_string();
            if ((it != pair.second.end()) && (next(it) != pair.second.end()))
                std::cout << ", ";
        }
        std::cout << "]" << std::endl;
    }
}

void
CLI::chooseInterface(int no)
{
    std::wstring w_iface = interfaces.at(no - 1);

    // setup converter
    using convert_type = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_type, wchar_t> converter;

    // use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
    std::string iface = converter.to_bytes(w_iface);
    network.setSpoofingInterface(iface);
}

void
CLI::chooseAccessPoint(int no)
{
    int i = 1;
    for (std::map<std::string, std::set<address_type>>::iterator iterator =
           aps.begin();
         iterator != aps.end();
         iterator++, i++) {
        if (i == no) {
            network.setBssid((*(iterator->second.begin())).to_string());
            break;
        }
    }
}

void
CLI::showAction()
{
    switch (state) {
        case CHOOSEIF:
            listInterfaces();
            int interfaceNo;
            std::cout << std::endl << std::endl << "[*] Choose the spoofing interface: ";
            std::cin >> interfaceNo;
            chooseInterface(interfaceNo);
            state = LISTAPS;
            break;
        case LISTAPS:
            listAccessPoints();
            int ap;
            std::cout << std::endl << std::endl << "[*] Choose the access point: ";
            std::cin >> ap;
            chooseAccessPoint(ap);
            state = ATTACK;
            break;
        case LISTHOSTS:
            listConnectedHosts();
            state = WHITELIST;
            break;
        case WHITELIST:
            state = CHOOSEIF;
            break;
        case ATTACK:
            attack();
            break;
    }
}

void
CLI::showMenu()
{
    if (state != WHITELIST)
        system("clear");
    showHeader();
    showAction();
}

void
CLI::attack()
{

    std::cout << "-> BSSID: " << network.getBssid() << std::endl;
    //std::cout << "-> Target: 40:b4:cd:6e:de:d5" << std::endl << std::endl;
    std::cout << "[*] Deauthenticating..." << std::endl;
    network.startDeauth();
    do 
    {
        std::cout << '\n' << "[*] Press enter to stop...";
    } while (std::cin.get() != '\n');
    network.stopDeauth();
}
