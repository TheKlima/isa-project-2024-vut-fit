## Compiler and flags
#CXX = g++
#CXXFLAGS = -std=c++20 -Wall -Wextra -Werror -pedantic -Iinclude # TODO maybe change it according to project's task
#DEPFLAGS = -MMD -MP
#LIBS = -lpcap
#
## Directories
#SRC_DIR = src
#OBJ_DIR = obj
#
## Target executable name
#TARGET = dns_monitor
#
## Source and object files
#SRCS = $(wildcard $(SRC_DIR)/*.cpp)
#OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))
#
## Dependency files
#DEPS = $(OBJS:.o=.d)
#
## Default target
#all: $(TARGET)
#
## Rule to create the target executable
#$(TARGET): $(OBJS)
#	$(CXX) $(CXXFLAGS) $^ -o $@ $(LIBS)
#
## Rule to create object files and generate dependencies
#$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
#	@mkdir -p $(OBJ_DIR)
#	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@
#
## Include the dependency files
#-include $(DEPS)
#
#zip:
#	cp -r include/* src/* .
#	zip xklyme00.tar *.c *.h Makefile *.pcapng *.pcap
#	rm -rf *.cpp *.h
#
## Clean up
#clean:
#	rm -rf $(OBJ_DIR)
#	rm -f dns_monitor
#
## Phony targets
#.PHONY: all clean

######

## Compiler and flags
#CXX = g++
#CXXFLAGS = -std=c++20 -Wall -Wextra -Werror -pedantic -Iinclude
#DEPFLAGS = -MMD -MP
#LIBS = -lpcap
#
## Directories
#SRC_DIR = src
#OBJ_DIR = obj
#
## Target executable name
#TARGET = dns_monitor
#
## Source and object files
#SRCS = $(wildcard $(SRC_DIR)/*.cpp)
#OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))
#
## Dependency files
#DEPS = $(OBJS:.o=.d)
#
## Default target
#all: $(TARGET)
#
## Rule to create the target executable
#$(TARGET): $(OBJS)
#	$(CXX) $(CXXFLAGS) $(OBJS) -o $@ $(LIBS)
#
## Rule to create object files and generate dependencies
#$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
#	@mkdir -p $(OBJ_DIR)
#	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@
#
## Include the dependency files
#-include $(DEPS)
#
## TODO tar!!!
##zip:
##	zip -r xklyme00.tar src include Makefile *.pcapng *.pcap
#
##zip:
##	cp -r include/* src/* .
##	zip xklyme00.tar *.cpp *.h Makefile *.pcapng *.pcap
##	rm -rf *.cpp *.h
#
##tar:
##	cp -r include/* src/* .
##	tar -cf xklyme00.tar *.cpp *.h Makefilee *.pcapng *.pcap
##	rm -rf *.cpp *.h
#
## Clean up
#clean:
#	rm -rf $(OBJ_DIR) $(TARGET) xklyme00.tar
#
#
## Phony targets
#.PHONY: all clean zip

# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -Werror -pedantic
LIBS = -lpcap

# Target executable name
TARGET = dns-monitor

# Source files (all .cpp files in the current directory)
SRCS = args.cpp dns-header.cpp dns-monitor.cpp dns-monitor-exception.cpp main.cpp packet-writer.cpp simple-packet-writer.cpp verbose-packet-writer.cpp

# Default target
all: $(TARGET)

# Rule to create the target executable
$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o $(TARGET) $(LIBS)

# Create an archive
tar:
	cp -r include/* src/* .
	tar -cf xklyme00.tar *.cpp *.h Makefile *.pcapng *.pcap README.md *.jpg manual.pdf
	rm -rf *.cpp *.h

# Clean up
clean:
	rm -f $(TARGET) xklyme00.tar

# Phony targets
.PHONY: all clean tar
