// File: dns_monitor_exception.h
// Subject: ISA
// Project: #1 (DNS monitor)
// Author: Andrii Klymenko
// Login: xklyme00
// Date: 22.4.2024

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