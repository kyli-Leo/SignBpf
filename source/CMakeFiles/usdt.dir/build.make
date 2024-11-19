# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.28

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/leo/Documents/libbpf-bootstrap/source

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/leo/Documents/libbpf-bootstrap/source

# Include any dependencies generated for this target.
include CMakeFiles/usdt.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/usdt.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/usdt.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/usdt.dir/flags.make

usdt.skel.h: usdt.bpf.o
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/leo/Documents/libbpf-bootstrap/source/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "[skel]  Building BPF skeleton: usdt"
	bash -c "/home/leo/Documents/libbpf-bootstrap/source/bpftool/bootstrap/bpftool gen skeleton /home/leo/Documents/libbpf-bootstrap/source/usdt.bpf.o > /home/leo/Documents/libbpf-bootstrap/source/usdt.skel.h"

usdt.bpf.o: usdt.bpf.c
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --blue --bold --progress-dir=/home/leo/Documents/libbpf-bootstrap/source/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "[clang] Building BPF object: usdt"
	/usr/bin/clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -idirafter /usr/lib/llvm-18/lib/clang/18/include -idirafter /usr/local/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include -I/home/leo/Documents/libbpf-bootstrap/source/../vmlinux.h/include/x86 -isystem /home/leo/Documents/libbpf-bootstrap/source/libbpf -c /home/leo/Documents/libbpf-bootstrap/source/usdt.bpf.c -o /home/leo/Documents/libbpf-bootstrap/source/usdt.bpf.o

CMakeFiles/usdt.dir/usdt.c.o: CMakeFiles/usdt.dir/flags.make
CMakeFiles/usdt.dir/usdt.c.o: usdt.c
CMakeFiles/usdt.dir/usdt.c.o: CMakeFiles/usdt.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/leo/Documents/libbpf-bootstrap/source/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/usdt.dir/usdt.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/usdt.dir/usdt.c.o -MF CMakeFiles/usdt.dir/usdt.c.o.d -o CMakeFiles/usdt.dir/usdt.c.o -c /home/leo/Documents/libbpf-bootstrap/source/usdt.c

CMakeFiles/usdt.dir/usdt.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/usdt.dir/usdt.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/leo/Documents/libbpf-bootstrap/source/usdt.c > CMakeFiles/usdt.dir/usdt.c.i

CMakeFiles/usdt.dir/usdt.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/usdt.dir/usdt.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/leo/Documents/libbpf-bootstrap/source/usdt.c -o CMakeFiles/usdt.dir/usdt.c.s

# Object files for target usdt
usdt_OBJECTS = \
"CMakeFiles/usdt.dir/usdt.c.o"

# External object files for target usdt
usdt_EXTERNAL_OBJECTS =

usdt: CMakeFiles/usdt.dir/usdt.c.o
usdt: CMakeFiles/usdt.dir/build.make
usdt: libbpf/libbpf.a
usdt: CMakeFiles/usdt.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/leo/Documents/libbpf-bootstrap/source/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking C executable usdt"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/usdt.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/usdt.dir/build: usdt
.PHONY : CMakeFiles/usdt.dir/build

CMakeFiles/usdt.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/usdt.dir/cmake_clean.cmake
.PHONY : CMakeFiles/usdt.dir/clean

CMakeFiles/usdt.dir/depend: usdt.bpf.o
CMakeFiles/usdt.dir/depend: usdt.skel.h
	cd /home/leo/Documents/libbpf-bootstrap/source && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/leo/Documents/libbpf-bootstrap/source /home/leo/Documents/libbpf-bootstrap/source /home/leo/Documents/libbpf-bootstrap/source /home/leo/Documents/libbpf-bootstrap/source /home/leo/Documents/libbpf-bootstrap/source/CMakeFiles/usdt.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/usdt.dir/depend
