# Set the minimum required version of CMake and define the project.
cmake_minimum_required(VERSION 3.18)
project(MyTelegramBot CXX)

# Add your executable and list its source files.
# IMPORTANT: Change "painelcity.cpp" if your main C++ file has a different name.
add_executable(bot_telegram_exe painelcity.cpp)

# Find the packages that vcpkg installed.
find_package(httplib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# Link the libraries to your executable.
target_link_libraries(bot_telegram_exe PRIVATE
    httplib::httplib
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
)
