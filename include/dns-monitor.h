/**
 * DNS monitor
 * 
 * @brief Definition of the class representing DNS monitor
 * @file dns-monitor.h
 * @author Andrii Klymenko <xklyme00>
 */

#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H

#include "args.h"
#include "dns-monitor-exception.h"
#include "packet-writer.h"
#include <pcap/pcap.h>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <csignal>

/**
 * @brief Class representing DNS monitor
 */
class Dns_monitor {
public:
    /**
     * @brief Constructs an object (assigns some values to its private members) based on the program arguments
     *
     * @param argc number of the program arguments + 1 (program's executable)
     * @param argv pointer to the array of the program arguments
     */
    Dns_monitor(int argc, char** argv);

    /**
     * @brief Deallocates memory of allocated object's resources
     */
    ~Dns_monitor();

    /**
     * @brief Prints out error buffer (object's private member m_err_buff)
     */
    void printErrBuff() const;

    /**
     * @brief Object's private member m_is_constructor_err "getter"
     *
     * @return Value of the object's private member m_is_constructor_err
     */
    bool getIsConstructorErr() const;

    /**
     * @brief Runs DNS monitor
     * 
     * Sequentially processes each DNS packet from a certain interface/pcap file until 
     * one of the signals SIGTERM, SIGINT, SIGQUIT was accepted or the all packets in the pcap file were processed.
     * Prints out each packet's information to stdout and to special files if needed.
     */
    void run();

    /**
     * @brief Handles accepted signal
     * 
     * Throws Dns_monitor_exception constructed with empty string which leads to the successful program termination.
     */
    static void signalHandler(int sig);
    
private:
    Args m_args;
    Packet_writer* m_packet_writer;
    bool m_is_constructor_err{};
    char m_err_buff[PCAP_ERRBUF_SIZE]{};
    pcap_t* m_pcap_handle{};
    const char* const m_dns_filter{};

    /**
     * @brief Creates pcap handle (object's private member m_pcap_handle)
     * 
     * Preparation before processing DNS packets.
     * Inspired by: https://vichargrave.github.io/programming/develop-a-packet-sniffer-with-libpcap/#process-packets
     */
    void createPcapHandle();
};

#endif // DNS_MONITOR_H
