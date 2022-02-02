# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)

# Here because why not ? CMAKE_ASM_NASM_OBJECT_FORMAT is checked when project is define.
# Hence early definition
set(CMAKE_ASM_NASM_OBJECT_FORMAT win64)

# Project name
project(AVXEncoder VERSION 1.0 LANGUAGES C ASM_NASM)

# Make makefile verbose to display command lines 
set(CMAKE_VERBOSE_MAKEFILE ON)

# Enable NASM
enable_language(ASM_NASM)

# Compile code
add_executable(AVXEncoder
	# NASM files
	"src/avx.asm"
	
	# C files
	"src/main.c"
)