# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "/home/leo/Documents/libbpf-bootstrap/source/../libbpf/src"
  "/home/leo/Documents/libbpf-bootstrap/source/libbpf/src/libbpf-build"
  "/home/leo/Documents/libbpf-bootstrap/source/libbpf"
  "/home/leo/Documents/libbpf-bootstrap/source/libbpf/tmp"
  "/home/leo/Documents/libbpf-bootstrap/source/libbpf/src/libbpf-stamp"
  "/home/leo/Documents/libbpf-bootstrap/source/libbpf/src"
  "/home/leo/Documents/libbpf-bootstrap/source/libbpf/src/libbpf-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/leo/Documents/libbpf-bootstrap/source/libbpf/src/libbpf-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/leo/Documents/libbpf-bootstrap/source/libbpf/src/libbpf-stamp${cfgdir}") # cfgdir has leading slash
endif()
