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
    bool m_is_verbose{};
    bool m_sniffing_from_interface{};
};

#endif // ARGS_H