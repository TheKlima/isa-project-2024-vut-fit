// File: dns_monitor_exception.cpp
// Subject: ISA
// Project: #1 (DNS monitor)
// Author: Andrii Klymenko
// Login: xklyme00
// Date: 22.4.2024

#include "dns_monitor_exception.h"

Dns_monitor_exception::Dns_monitor_exception(std::string_view explanation)
    :
    m_explanation{explanation}
{

}

// returns description explanation
const char* Dns_monitor_exception::what() const noexcept
{
    return m_explanation.c_str();
}