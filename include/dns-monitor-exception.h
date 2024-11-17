/**
 * DNS monitor
 * 
 * @brief Definition of the class representing program's exception
 * @file args.h
 * @author Andrii Klymenko <xklyme00>
 */

#ifndef DNS_MONITOR_EXCEPTION_H
#define DNS_MONITOR_EXCEPTION_H

#include <exception>
#include <string>

// custom DNS Monitor exception
class Dns_monitor_exception : public std::exception {
private:
    const std::string m_explanation{};

public:
    Dns_monitor_exception(std::string_view explanation);
    const char* what() const noexcept override;
};

#endif // DNS_MONITOR_EXCEPTION_H