#ifndef CLI_H
#define CLI_H

#include <string>
#include <unistd.h>
#include <cassert>
#include <Network.h>
#include <clocale>
#include <locale>
#include <vector>
#include <codecvt>

class CLI
{
    enum State {
        CHOOSEIF,
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
        void showMenu();
        void showHeader();
        void showAction();
        void listInterfaces();
        void chooseInterface(int no);
        void attack();
};

#endif // CLI_H
