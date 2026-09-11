cmake_minimum_required(VERSION 3.20)
project(onetime LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    # 全目标静态 CRT（/MT）：单文件可执行，目标机免装 VC 运行库。
    # 必须在 add_subdirectory 之前设置，保证 EUI-NEO 各目标一致。
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# EUI-NEO：源码接入（3rd/EUI-NEO，见 README），离线 bundled 依赖，不带自带示例
set(EUI_DEPS_MODE "bundled" CACHE STRING "" FORCE)
set(EUI_BUILD_APPS OFF CACHE BOOL "" FORCE)
set(EUI_BUILD_USER_APPS OFF CACHE BOOL "" FORCE)
set(EUI_ENABLE_MARKDOWN OFF CACHE BOOL "" FORCE)
# 托盘：Windows 默认启用；Linux 需要 glib/gio 或 GTK3+libappindicator（且需
# pkg-config），缺失时 EUI-NEO 配置直接失败——默认关闭但可被 -D 覆盖重开
# （见 docs/linux-build.md）。
if(WIN32)
    set(EUI_ENABLE_TRAY ON CACHE BOOL "" FORCE)
elseif(NOT DEFINED EUI_ENABLE_TRAY)
    set(EUI_ENABLE_TRAY OFF CACHE BOOL "" FORCE)
endif()
add_subdirectory(3rd/EUI-NEO)

# 服务端核心（无 GUI 依赖，onetime_tests 只链这一份）
add_library(onetime_core STATIC
    src/server.cpp
    src/util.cpp)
if(WIN32)
    target_sources(onetime_core PRIVATE src/crypto_win.cpp)
    target_link_libraries(onetime_core PUBLIC bcrypt ws2_32)
else()
    target_sources(onetime_core PRIVATE src/crypto_posix.cpp)
    find_package(Threads REQUIRED)
    target_link_libraries(onetime_core PUBLIC Threads::Threads)
endif()
target_include_directories(onetime_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

# GUI 应用（EUI-NEO 前端 + 内置服务线程）
add_executable(onetime src/main.cpp)
if(WIN32)
    # exe 图标：接管 EUI 默认的图标资源位（eui_neo_configure_app 会把全局属性
    # EUI_NEO_APP_ICON_RESOURCE 挂到 app 目标），改指本项目 assets/icon.ico。
    # 资源名必须是 GLFW_ICON：bundled GLFW 窗口类自动加载（窗口/任务栏/Alt-Tab，
    # 见 3rd/EUI-NEO/3rd/glfw/src/win32_window.c），托盘 ExtractIconEx 同样取它。
    # rc 的资源文件路径用绝对路径生成，规避 rc.exe 工作目录不确定性。
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/assets/icon.ico" ONETIME_ICON_NATIVE)
    string(REPLACE "\\" "\\\\" ONETIME_ICON_ESCAPED "${ONETIME_ICON_NATIVE}")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/onetime_app_icon.rc"
         "GLFW_ICON ICON \"${ONETIME_ICON_ESCAPED}\"\n")
    set_property(GLOBAL PROPERTY EUI_NEO_APP_ICON_RESOURCE
                 "${CMAKE_CURRENT_BINARY_DIR}/onetime_app_icon.rc")
endif()
eui_neo_configure_app(onetime)
target_link_libraries(onetime PRIVATE onetime_core)

# 安全不变量测试（纯控制台，不链 EUI）
add_executable(onetime_tests tests/test_main.cpp)
target_link_libraries(onetime_tests PRIVATE onetime_core)

if(MSVC)
    # Release：速度优先（/O2），函数级分离 + LTCG + 去未引用代码兼顾体积
    # /utf-8：源码为 UTF-8（中文注释/文案），避免 CP936 代码页误解析
    foreach(t onetime_core onetime onetime_tests)
        target_compile_options(${t} PRIVATE
            /utf-8
            $<$<CONFIG:Release>:/O2;/GF;/Gy;/Gw;/Zc:inline>)
        target_link_options(${t} PRIVATE
            $<$<CONFIG:Release>:/LTCG;/OPT:REF;/OPT:ICF;/INCREMENTAL:NO>)
    endforeach()
else()
    # GCC/Clang：Release 无默认优化，显式 -O2；源码按 UTF-8 处理
    foreach(t onetime_core onetime onetime_tests)
        target_compile_options(${t} PRIVATE
            -finput-charset=UTF-8
            $<$<CONFIG:Release>:-O2>)
    endforeach()
endif()
