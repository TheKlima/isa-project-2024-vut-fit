/**
 * DNS monitor
 * 
 * @brief Program's entry point
 * @file main.cpp
 * @author Andrii Klymenko <xklyme00>
 */

#include "dns-monitor.h"
#include <cstdlib>

int main(int argc, char** argv) try
{
    Dns_monitor dns_monitor{argc, argv};

    if(dns_monitor.getIsConstructorErr())
    {
        dns_monitor.printErrBuff();
        return EXIT_FAILURE;
    }

    dns_monitor.run();
    return EXIT_SUCCESS;
}
catch (std::exception& e)
{
    // in case when the program gets one of these signals: SIGTERM, SIGINT, SIGQUIT
    if(e.what() != nullptr && std::strlen(e.what()) == 0)
    {
        return EXIT_SUCCESS;
    }

    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
}
