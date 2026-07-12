#include "hermes_runtime_internal.h"

#include <arpa/inet.h>
#include <cmath>
#include <cstdlib>
#include <cstdio>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pwd.h>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unordered_map>
#include <unistd.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <net/if_dl.h>
#include <sys/sysctl.h>
#elif defined(__linux__)
#include <netpacket/packet.h>
#include <sys/sysinfo.h>
#else
#include <sys/sysinfo.h>
#endif

void installOsInfoGlobals(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;

  auto authorizeSystemInfoFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactAuthorizeSystemInfo"),
      1,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value* args,
         size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isNumber()) {
          throw facebook::jsi::JSError(
              runtime, "__exactAuthorizeSystemInfo: information kind required");
        }
        double raw = args[0].asNumber();
        if (!std::isfinite(raw) || raw < 0 || raw > 15 || std::floor(raw) != raw) {
          throw facebook::jsi::JSError(
              runtime, "__exactAuthorizeSystemInfo: invalid information kind");
        }
        auto name =
            static_cast<ExactSystemInfoName>(static_cast<uint32_t>(raw));
        exactRequireTypedSystemInfo(
            runtime,
            ExactSystemInfoSurface::CachedValue,
            name);
        // @ref LLP 0021#typed-resources-and-initial-vocabulary — storage-path
        // values cross the disclosure barrier only after the sys:read gate;
        // routing back through process.env would require unrelated env:read
        // authority and make the generated builtin effect model incomplete.
        if (name == ExactSystemInfoName::StoragePaths) {
          const auto environmentValue = [](const char* key) -> std::string {
            const char* value = std::getenv(key);
            return value ? std::string(value) : std::string();
          };
          auto home = environmentValue("HOME");
          if (home.empty()) home = environmentValue("USERPROFILE");
          if (home.empty()) home = "/";
          auto temporary = environmentValue("TMPDIR");
          if (temporary.empty()) temporary = environmentValue("TMP");
          if (temporary.empty()) temporary = environmentValue("TEMP");
          if (temporary.empty()) temporary = "/tmp";
          facebook::jsi::Object paths(runtime);
          paths.setProperty(runtime, "home", home);
          paths.setProperty(runtime, "temporary", temporary);
          return paths;
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(
      rt, "__exactAuthorizeSystemInfo", std::move(authorizeSystemInfoFn));

  auto getHostnameFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetHostname"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        exactRequireTypedSystemInfo(
            runtime, ExactSystemInfoSurface::Hostname, ExactSystemInfoName::Hostname);
        char hostname[256];
        if (gethostname(hostname, sizeof(hostname)) != 0) {
          return facebook::jsi::Value(
              facebook::jsi::String::createFromUtf8(runtime, "localhost"));
        }
        hostname[sizeof(hostname) - 1] = '\0';
        return facebook::jsi::Value(facebook::jsi::String::createFromUtf8(runtime, hostname));
      });
  rt.global().setProperty(rt, "__exactGetHostname", std::move(getHostnameFn));

  auto getCpuCountFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetCpuCount"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        exactRequireTypedSystemInfo(
            runtime, ExactSystemInfoSurface::CpuCount, ExactSystemInfoName::Cpus);
#if defined(__APPLE__)
        int cpuCount = 0;
        size_t cpuSize = sizeof(cpuCount);
        if (sysctlbyname("hw.ncpu", &cpuCount, &cpuSize, nullptr, 0) == 0) {
          return facebook::jsi::Value(static_cast<double>(cpuCount));
        }
        return facebook::jsi::Value(1.0);
#else
        long cpuCount = sysconf(_SC_NPROCESSORS_ONLN);
        if (cpuCount < 1) cpuCount = 1;
        return facebook::jsi::Value(static_cast<double>(cpuCount));
#endif
      });
  rt.global().setProperty(rt, "__exactGetCpuCount", std::move(getCpuCountFn));

  auto getTotalMemFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetTotalMem"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        exactRequireTypedSystemInfo(
            runtime, ExactSystemInfoSurface::TotalMemory, ExactSystemInfoName::Memory);
#if defined(__APPLE__)
        uint64_t memsize = 0;
        size_t memSizeLen = sizeof(memsize);
        if (sysctlbyname("hw.memsize", &memsize, &memSizeLen, nullptr, 0) == 0) {
          return facebook::jsi::Value(static_cast<double>(memsize));
        }
        return facebook::jsi::Value(0.0);
#else
        long pages = sysconf(_SC_PHYS_PAGES);
        long pageSize = sysconf(_SC_PAGESIZE);
        if (pages > 0 && pageSize > 0) {
          return facebook::jsi::Value(static_cast<double>(pages) *
                                      static_cast<double>(pageSize));
        }
        return facebook::jsi::Value(0.0);
#endif
      });
  rt.global().setProperty(rt, "__exactGetTotalMem", std::move(getTotalMemFn));

  auto getFreeMemFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetFreeMem"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        exactRequireTypedSystemInfo(
            runtime, ExactSystemInfoSurface::FreeMemory, ExactSystemInfoName::Memory);
#if defined(__APPLE__)
        vm_size_t vmPageSize;
        mach_msg_type_number_t vmCount = HOST_VM_INFO_COUNT;
        vm_statistics_data_t vmStats;
        if (host_page_size(mach_host_self(), &vmPageSize) == KERN_SUCCESS &&
            host_statistics(mach_host_self(),
                            HOST_VM_INFO,
                            reinterpret_cast<host_info_t>(&vmStats),
                            &vmCount) == KERN_SUCCESS) {
          uint64_t freeMem =
              static_cast<uint64_t>(vmStats.free_count) * static_cast<uint64_t>(vmPageSize);
          return facebook::jsi::Value(static_cast<double>(freeMem));
        }
        return facebook::jsi::Value(0.0);
#else
        long pages = sysconf(_SC_AVPHYS_PAGES);
        long pageSize = sysconf(_SC_PAGESIZE);
        if (pages > 0 && pageSize > 0) {
          return facebook::jsi::Value(static_cast<double>(pages) *
                                      static_cast<double>(pageSize));
        }
        return facebook::jsi::Value(0.0);
#endif
      });
  rt.global().setProperty(rt, "__exactGetFreeMem", std::move(getFreeMemFn));

  auto getUptimeFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetUptime"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        exactRequireTypedSystemInfo(
            runtime, ExactSystemInfoSurface::Uptime, ExactSystemInfoName::Uptime);
#if defined(__APPLE__)
        struct timeval boottime;
        size_t btSize = sizeof(boottime);
        int mib[2] = {CTL_KERN, KERN_BOOTTIME};
        if (sysctl(mib, 2, &boottime, &btSize, nullptr, 0) == 0) {
          struct timeval now;
          gettimeofday(&now, nullptr);
          double uptime = static_cast<double>(now.tv_sec - boottime.tv_sec) +
                          static_cast<double>(now.tv_usec - boottime.tv_usec) / 1000000.0;
          return facebook::jsi::Value(uptime);
        }
        return facebook::jsi::Value(0.0);
#else
        struct sysinfo sysInfo;
        if (sysinfo(&sysInfo) == 0) {
          return facebook::jsi::Value(static_cast<double>(sysInfo.uptime));
        }
        return facebook::jsi::Value(0.0);
#endif
      });
  rt.global().setProperty(rt, "__exactGetUptime", std::move(getUptimeFn));

  auto getUserInfoFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetUserInfo"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        exactRequireTypedSystemInfo(
            runtime, ExactSystemInfoSurface::UserInfo, ExactSystemInfoName::User);
        facebook::jsi::Object info(runtime);
        uid_t uid = getuid();
        gid_t gid = getgid();
        info.setProperty(runtime, "uid", facebook::jsi::Value(static_cast<double>(uid)));
        info.setProperty(runtime, "gid", facebook::jsi::Value(static_cast<double>(gid)));

        struct passwd* pw = getpwuid(uid);
        if (pw) {
          if (pw->pw_name) {
            info.setProperty(runtime,
                             "username",
                             facebook::jsi::String::createFromUtf8(runtime, pw->pw_name));
          } else {
            info.setProperty(runtime,
                             "username",
                             facebook::jsi::String::createFromUtf8(runtime, ""));
          }
          if (pw->pw_dir) {
            info.setProperty(runtime,
                             "homedir",
                             facebook::jsi::String::createFromUtf8(runtime, pw->pw_dir));
          } else {
            info.setProperty(runtime,
                             "homedir",
                             facebook::jsi::String::createFromUtf8(runtime, "/"));
          }
          if (pw->pw_shell) {
            info.setProperty(runtime,
                             "shell",
                             facebook::jsi::String::createFromUtf8(runtime, pw->pw_shell));
          } else {
            info.setProperty(runtime, "shell", facebook::jsi::Value::null());
          }
        } else {
          info.setProperty(runtime,
                           "username",
                           facebook::jsi::String::createFromUtf8(runtime, ""));
          info.setProperty(runtime,
                           "homedir",
                           facebook::jsi::String::createFromUtf8(runtime, "/"));
          info.setProperty(runtime, "shell", facebook::jsi::Value::null());
        }
        return info;
      });
  rt.global().setProperty(rt, "__exactGetUserInfo", std::move(getUserInfoFn));

  auto getLoadAvgFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetLoadAvg"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        exactRequireTypedSystemInfo(
            runtime, ExactSystemInfoSurface::LoadAverage, ExactSystemInfoName::LoadAverage);
        double loadavgArr[3] = {0.0, 0.0, 0.0};
#if !defined(EXACT_PLATFORM_ANDROID)
        getloadavg(loadavgArr, 3);
#endif
        auto arr = facebook::jsi::Array(runtime, 3);
        arr.setValueAtIndex(runtime, 0, facebook::jsi::Value(loadavgArr[0]));
        arr.setValueAtIndex(runtime, 1, facebook::jsi::Value(loadavgArr[1]));
        arr.setValueAtIndex(runtime, 2, facebook::jsi::Value(loadavgArr[2]));
        return arr;
      });
  rt.global().setProperty(rt, "__exactGetLoadAvg", std::move(getLoadAvgFn));

  auto getNetIfsFn = facebook::jsi::Function::createFromHostFunction(
      rt,
      facebook::jsi::PropNameID::forAscii(rt, "__exactGetNetworkInterfaces"),
      0,
      [](facebook::jsi::Runtime& runtime,
         const facebook::jsi::Value&,
         const facebook::jsi::Value*,
         size_t) -> facebook::jsi::Value {
        exactRequireTypedSystemInfo(
            runtime,
            ExactSystemInfoSurface::NetworkInterfaces,
            ExactSystemInfoName::NetworkInterfaces);
        auto result = facebook::jsi::Object(runtime);
        struct ifaddrs* ifaddr = nullptr;
        if (getifaddrs(&ifaddr) == -1) {
          return result;
        }
        auto formatMac = [](const unsigned char* bytes, size_t length) -> std::string {
          if (!bytes || length < 6) {
            return "00:00:00:00:00:00";
          }
          char mac[18];
          std::snprintf(mac,
                        sizeof(mac),
                        "%02x:%02x:%02x:%02x:%02x:%02x",
                        bytes[0],
                        bytes[1],
                        bytes[2],
                        bytes[3],
                        bytes[4],
                        bytes[5]);
          return mac;
        };
        std::unordered_map<std::string, std::string> macByName;
        std::unordered_map<std::string, std::vector<struct ifaddrs*>> ifmap;
        for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
          if (ifa->ifa_addr == nullptr) continue;
          int family = ifa->ifa_addr->sa_family;
#if defined(__linux__)
          // @ref LLP 0008#os-info — Linux exposes interface MAC addresses via AF_PACKET entries from getifaddrs().
          if (family == AF_PACKET) {
            auto* link = reinterpret_cast<struct sockaddr_ll*>(ifa->ifa_addr);
            if (ifa->ifa_name && link->sll_halen >= 6) {
              macByName[ifa->ifa_name] =
                  formatMac(reinterpret_cast<const unsigned char*>(link->sll_addr),
                            static_cast<size_t>(link->sll_halen));
            }
            continue;
          }
#elif defined(__APPLE__)
          // @ref LLP 0008#os-info — Apple exposes interface MAC addresses via AF_LINK entries from getifaddrs().
          if (family == AF_LINK) {
            auto* link = reinterpret_cast<struct sockaddr_dl*>(ifa->ifa_addr);
            if (ifa->ifa_name && link->sdl_alen >= 6) {
              macByName[ifa->ifa_name] =
                  formatMac(reinterpret_cast<const unsigned char*>(LLADDR(link)),
                            static_cast<size_t>(link->sdl_alen));
            }
            continue;
          }
#endif
          if (family != AF_INET && family != AF_INET6) continue;
          ifmap[ifa->ifa_name].push_back(ifa);
        }
        for (auto& [name, entries] : ifmap) {
          auto arr = facebook::jsi::Array(runtime, entries.size());
          for (size_t i = 0; i < entries.size(); i++) {
            struct ifaddrs* ifa = entries[i];
            auto entry = facebook::jsi::Object(runtime);
            char addrBuf[INET6_ADDRSTRLEN] = {0};
            char maskBuf[INET6_ADDRSTRLEN] = {0};
            int family = ifa->ifa_addr->sa_family;
            int prefixLen = 0;
            if (family == AF_INET) {
              auto* sin = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
              inet_ntop(AF_INET, &sin->sin_addr, addrBuf, sizeof(addrBuf));
              if (ifa->ifa_netmask) {
                auto* mask = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_netmask);
                inet_ntop(AF_INET, &mask->sin_addr, maskBuf, sizeof(maskBuf));
                uint32_t m = ntohl(mask->sin_addr.s_addr);
                while (m & 0x80000000) {
                  prefixLen++;
                  m <<= 1;
                }
              }
              entry.setProperty(
                  runtime,
                  "family",
                  facebook::jsi::String::createFromAscii(runtime, "IPv4"));
            } else {
              auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_addr);
              inet_ntop(AF_INET6, &sin6->sin6_addr, addrBuf, sizeof(addrBuf));
              if (ifa->ifa_netmask) {
                auto* mask6 = reinterpret_cast<struct sockaddr_in6*>(ifa->ifa_netmask);
                inet_ntop(AF_INET6, &mask6->sin6_addr, maskBuf, sizeof(maskBuf));
                for (int b = 0; b < 16; b++) {
                  uint8_t byte = mask6->sin6_addr.s6_addr[b];
                  while (byte & 0x80) {
                    prefixLen++;
                    byte <<= 1;
                  }
                  if (byte == 0 && mask6->sin6_addr.s6_addr[b] != 0xff) break;
                }
              }
              entry.setProperty(
                  runtime,
                  "family",
                  facebook::jsi::String::createFromAscii(runtime, "IPv6"));
            }
            entry.setProperty(
                runtime, "address", facebook::jsi::String::createFromAscii(runtime, addrBuf));
            entry.setProperty(
                runtime, "netmask", facebook::jsi::String::createFromAscii(runtime, maskBuf));
            bool isInternal = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
            entry.setProperty(runtime, "internal", facebook::jsi::Value(isInternal));
            auto macIt = macByName.find(name);
            const char* mac = macIt == macByName.end() ? "00:00:00:00:00:00" : macIt->second.c_str();
            entry.setProperty(
                runtime,
                "mac",
                facebook::jsi::String::createFromAscii(runtime, mac));
            std::string cidr = std::string(addrBuf) + "/" + std::to_string(prefixLen);
            entry.setProperty(
                runtime, "cidr", facebook::jsi::String::createFromAscii(runtime, cidr));
            arr.setValueAtIndex(runtime, i, std::move(entry));
          }
          result.setProperty(
              runtime, facebook::jsi::String::createFromAscii(runtime, name), std::move(arr));
        }
        freeifaddrs(ifaddr);
        return result;
      });
  rt.global().setProperty(rt, "__exactGetNetworkInterfaces", std::move(getNetIfsFn));
}
