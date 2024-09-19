#ifndef ARGS_H
#define ARGS_H

class Args {
public:
    Args(int argc, char** argv);
    
    const char* getPacketsSource() const;
    bool getIsVerbose() const;
    
private:
    const char* m_packets_source{};
    bool m_is_verbose{};
};

#endif // ARGS_H