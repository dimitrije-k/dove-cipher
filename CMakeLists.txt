cmake_minimum_required(VERSION 3.8.0)

project(Dove)

add_library(dove STATIC src/dove.c)
target_include_directories(dove PUBLIC include)