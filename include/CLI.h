#ifndef CLI_H
#define CLI_H

#include <tins/tins.h>
#include <string>
#include <unistd.h>
#include <cassert>


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
        void showMenu();
        void showHeader();
        void showAction();
        void listInterfaces();
        void attack();
};

#endif // CLI_H
