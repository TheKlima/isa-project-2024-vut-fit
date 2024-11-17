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

/**
 * @brief Class representing custom program's exception
 */
class Dns_monitor_exception : public std::exception {
private:
    const std::string m_explanation{}; // exception's explanation

public:
    /**
     * @brief Constructs an object (assigns some value to its private member m_explanation)
     *
     * @param explanation exception's cause
     */
    Dns_monitor_exception(std::string_view explanation);

    /**
     * @brief Returns a pointer to the object's private member m_explanation
     *
     * @return string containing exception's cause
     */
    const char* what() const noexcept override;
};

#endif // DNS_MONITOR_EXCEPTION_H
