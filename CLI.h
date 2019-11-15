#ifndef CLI_H
#define CLI_H

#include <string>
#include <unistd.h>
#include <cassert>
#include <clocale>
#include <locale>
#include <vector>
#include <codecvt>
#include <iostream>

#include "Network.h"

class CLI
{
    typedef Tins::Dot11::address_type address_type;

    enum State {
        CHOOSEIF,
        LISTAPS,
        LISTHOSTS,
        WHITELIST,
        ATTACK
    };

    public:
        CLI();
        virtual ~CLI();
        void mainLoop();

    protected:

    private:
        State state;
        Network network;
        std::vector<std::wstring> interfaces;
        std::map<std::string, std::set<address_type>> aps;
        std::vector<std::string> targets;
        void showMenu();
        void showHeader();
        void showAction();
        void listInterfaces();
        void listAccessPoints();
        void chooseInterface(int no);
        void chooseAccessPoint(int no);
        void listConnectedHosts();
        void attack();
};

#endif // CLI_H
