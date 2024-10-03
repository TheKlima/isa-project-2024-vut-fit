#ifndef ARGS_H
#define ARGS_H

class Args {
public:
    Args(int argc, char** argv);
    
    const char* getPacketsSource() const;
    bool getIsVerbose() const;
    bool getSniffingFromInterface() const;
    
private:
    const char* m_packets_source{};
    const char* m_domains_file_name{};
    const char* m_translations_file_name{};
    bool m_is_verbose{};
    bool m_sniffing_from_interface{};
};

#endif // ARGS_H