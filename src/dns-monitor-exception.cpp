/**
 * DNS monitor
 * 
 * @brief Implementation of the Dns_monitor_exception class
 * @file args.cpp
 * @author Andrii Klymenko <xklyme00>
 */

#include "dns-monitor-exception.h"

Dns_monitor_exception::Dns_monitor_exception(std::string_view explanation)
    :
    m_explanation{explanation}
{

}

const char* Dns_monitor_exception::what() const noexcept
{
    return m_explanation.c_str();
}
