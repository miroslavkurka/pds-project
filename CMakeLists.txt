cmake_minimum_required(VERSION 3.10)

# Project name
project(PDS_crack LANGUAGES C CUDA)

# Find CUDA
find_package(CUDAToolkit REQUIRED)

# Add executable
add_executable(pds_crack cracker.cu md5.cu)

# Link CUDA libraries
target_link_libraries(pds_crack CUDA::cudart)
