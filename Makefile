# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -Werror -pedantic -Iinclude # TODO maybe change it according to project's task
DEPFLAGS = -MMD -MP

# Directories
SRC_DIR = src
OBJ_DIR = obj

# Target executable name
TARGET = dns_monitor

# Source and object files
SRCS = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SRCS))

# Dependency files
DEPS = $(OBJS:.o=.d)

# Default target
all: $(TARGET)

# Rule to create the target executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@

# Rule to create object files and generate dependencies
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

# Include the dependency files
-include $(DEPS)

# Clean up
clean:
	rm dns_monitor
	rm -rf $(OBJ_DIR)

# Phony targets
.PHONY: all clean
