# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/leo/Documents/libbpf-bootstrap/source/../bpftool/src"
  "/home/leo/Documents/libbpf-bootstrap/source/bpftool/src/bpftool-build"
  "/home/leo/Documents/libbpf-bootstrap/source/bpftool"
  "/home/leo/Documents/libbpf-bootstrap/source/bpftool/tmp"
  "/home/leo/Documents/libbpf-bootstrap/source/bpftool/src/bpftool-stamp"
  "/home/leo/Documents/libbpf-bootstrap/source/bpftool/src"
  "/home/leo/Documents/libbpf-bootstrap/source/bpftool/src/bpftool-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/leo/Documents/libbpf-bootstrap/source/bpftool/src/bpftool-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/leo/Documents/libbpf-bootstrap/source/bpftool/src/bpftool-stamp${cfgdir}") # cfgdir has leading slash
endif()
