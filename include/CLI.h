#ifndef CLI_H
#define CLI_H

#include <string>
#include <unistd.h>
#include <cassert>
#include <Network.h>


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
        void showMenu();
        void showHeader();
        void showAction();
        void listInterfaces();
        void attack();
};

#endif // CLI_H
