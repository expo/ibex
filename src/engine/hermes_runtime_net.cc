#include "hermes_runtime_internal.h"

#include <arpa/inet.h>
#include <cmath>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <limits>
#include <poll.h>
#include <random>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

extern "C" int32_t ex_host_is_armed(void);
extern "C" int32_t ex_host_typed_generations(
    uint64_t* negative_generation,
    uint64_t* dynamic_generation,
    uint64_t* handle_generation);
extern "C" int32_t ex_host_authorize_typed_network_stack(
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    uint32_t network_kind,
    const char* host,
    uint16_t port,
    uint32_t stage,
    const char* candidates_json,
    const char* selected_candidate,
    const char* verified_peer,
    const char* connection_id,
    uint64_t redirect_index);
extern "C" int32_t ex_host_authorize_typed_udp_datagram_stack(
    uint64_t module_id,
    const uint64_t* module_ids,
    size_t module_ids_len,
    const char* host,
    uint16_t port,
    const char* connection_id);

namespace {

struct SocketEntry {
  int fd = -1;
  uint64_t identity = 0;
  uint64_t fdDevice = 0;
  uint64_t fdInode = 0;
  bool fdIdentityKnown = false;
  uint64_t runtimeNonce = 0;
  uint64_t owner = 0;
  std::string capability;
  bool typedConnect = false;
  bool typedListen = false;
  bool typedPending = false;
  std::string typedHost;
  uint16_t typedPort = 0;
  std::string typedCandidates;
  std::string typedSelected;
  std::string typedPeer;
  std::string typedConnectionId;
  bool typedAuthorizationGenerationsInitialized = false;
  uint64_t typedNegativeGeneration = 0;
  uint64_t typedDynamicGeneration = 0;
  uint64_t typedHandleGeneration = 0;
  std::vector<uint64_t> typedAuthorizationPrincipals;
  uint32_t typedListenOperationKind = 0;
  std::string typedListenHost;
  uint16_t typedListenPort = 0;
  bool typedListenDualStack = false;
  std::string typedListenBoundAddress;
  uint16_t typedListenBoundPort = 0;
  std::string typedListenerId;
  std::string typedAcceptedAddress;
  uint16_t typedAcceptedPort = 0;
  bool typedUdpAuthorizationGenerationsInitialized = false;
  std::string typedUdpHost;
  uint16_t typedUdpPort = 0;
  uint64_t typedUdpNegativeGeneration = 0;
  uint64_t typedUdpDynamicGeneration = 0;
  uint64_t typedUdpHandleGeneration = 0;
  std::vector<uint64_t> typedUdpAuthorizationPrincipals;
};

static std::unordered_map<int, SocketEntry> g_socket_handles;
static int g_next_socket_handle = 1;
static uint64_t g_next_socket_identity = 1;
static std::mutex g_socket_mutex;

struct NetOwnerStampEntry {
  uint64_t runtimeNonce = 0;
  uint64_t owner = 0;
};

static std::unordered_map<uint64_t, NetOwnerStampEntry> g_net_owner_stamps;
static std::mutex g_net_owner_stamp_mutex;

uint64_t netOwnerStampForCurrentPrincipal() {
  const uint64_t runtimeNonce = exactCurrentRuntimeNonce();
  const uint64_t owner = currentPrincipalId();
  if (runtimeNonce == 0) return 0;
  std::lock_guard<std::mutex> lock(g_net_owner_stamp_mutex);
  for (const auto& item : g_net_owner_stamps) {
    if (item.second.runtimeNonce == runtimeNonce && item.second.owner == owner) {
      return item.first;
    }
  }
  static std::random_device randomDevice;
  constexpr uint64_t kJsSafeMask = (uint64_t{1} << 53) - 1;
  for (size_t attempt = 0; attempt < 128; ++attempt) {
    uint64_t stamp =
        ((static_cast<uint64_t>(randomDevice()) << 32) ^
         static_cast<uint64_t>(randomDevice())) &
        kJsSafeMask;
    if (stamp == 0 || g_net_owner_stamps.count(stamp) != 0) continue;
    g_net_owner_stamps.emplace(stamp, NetOwnerStampEntry{runtimeNonce, owner});
    return stamp;
  }
  return 0;
}

void requireNetOwnerStamp(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value) {
  constexpr double kMaxSafeInteger = 9007199254740991.0;
  if (!value.isNumber()) {
    throw facebook::jsi::JSError(runtime, "__exactNetOwner: numeric stamp required");
  }
  const double number = value.asNumber();
  if (!std::isfinite(number) || number < 1.0 || number > kMaxSafeInteger ||
      std::floor(number) != number) {
    throw facebook::jsi::JSError(runtime, "__exactNetOwner: invalid stamp");
  }
  const uint64_t stamp = static_cast<uint64_t>(number);
  std::lock_guard<std::mutex> lock(g_net_owner_stamp_mutex);
  auto item = g_net_owner_stamps.find(stamp);
  if (item == g_net_owner_stamps.end() ||
      item->second.runtimeNonce != exactCurrentRuntimeNonce() ||
      item->second.owner != currentPrincipalId()) {
    throw facebook::jsi::JSError(
        runtime, "__exactNetOwner: stamp belongs to another runtime or principal");
  }
}

int requireNetOwnerSocketHandle(
    facebook::jsi::Runtime& runtime,
    const facebook::jsi::Value& value) {
  constexpr double kMaxSafeInteger = 9007199254740991.0;
  if (!value.isNumber()) {
    throw facebook::jsi::JSError(
        runtime, "__exactNetOwner: numeric handle required");
  }
  const double number = value.asNumber();
  if (!std::isfinite(number) || number < 1.0 ||
      number > kMaxSafeInteger || std::floor(number) != number ||
      number > static_cast<double>(std::numeric_limits<int>::max())) {
    throw facebook::jsi::JSError(runtime, "__exactNetOwner: invalid handle");
  }
  return static_cast<int>(number);
}

void cleanupRuntimeNetOwnerStamps(uint64_t runtimeNonce) {
  std::lock_guard<std::mutex> lock(g_net_owner_stamp_mutex);
  for (auto item = g_net_owner_stamps.begin(); item != g_net_owner_stamps.end();) {
    if (item->second.runtimeNonce == runtimeNonce) {
      item = g_net_owner_stamps.erase(item);
    } else {
      ++item;
    }
  }
}

void captureSocketFdIdentity(SocketEntry& entry) {
  struct stat status = {};
  entry.fdIdentityKnown = entry.fd >= 0 && ::fstat(entry.fd, &status) == 0;
  if (entry.fdIdentityKnown) {
    entry.fdDevice = static_cast<uint64_t>(status.st_dev);
    entry.fdInode = static_cast<uint64_t>(status.st_ino);
  }
}

bool socketFdIdentityMatches(const SocketEntry& entry) {
  struct stat status = {};
  return entry.fdIdentityKnown && entry.fd >= 0 &&
      ::fstat(entry.fd, &status) == 0 &&
      entry.fdDevice == static_cast<uint64_t>(status.st_dev) &&
      entry.fdInode == static_cast<uint64_t>(status.st_ino);
}

void cleanupRuntimeSockets(uint64_t runtimeNonce) {
  std::lock_guard<std::mutex> lock(g_socket_mutex);
  for (auto it = g_socket_handles.begin(); it != g_socket_handles.end();) {
    if (it->second.runtimeNonce == runtimeNonce) {
      // Keep the identity check and close under the registry lock. If an fd was
      // closed/reused outside this registry, erase the stale handle without
      // closing the unrelated replacement object.
      if (socketFdIdentityMatches(it->second)) ::close(it->second.fd);
      it = g_socket_handles.erase(it);
    } else {
      ++it;
    }
  }
}

std::string networkEndpointCapability(const char* base, const std::string& host, int port) {
  return std::string(base) + ":" + formatNetworkEndpoint(host, port);
}

void requireNetworkCapability(
    facebook::jsi::Runtime& runtime,
    const std::string& capability,
    const char* description) {
  if (!checkCapability(capability)) {
    std::string message =
        std::string("Permission denied: ") + description + " capability required";
    throw facebook::jsi::JSError(runtime, message.c_str());
  }
}

bool principalMayAdoptRawSocket(uint64_t principal) {
  if (principal == 0) {
    return true;
  }
#ifdef EXACT_HAVE_FRAME_ATTRIBUTION
  if (principal == static_cast<uint64_t>(kRuntimePrincipalId)) {
    return true;
  }
#endif
  return false;
}

void requireRawSocketAdoptionAllowed(facebook::jsi::Runtime& runtime, int fd, const char* syscall) {
  if (principalMayAdoptRawSocket(currentPrincipalId())) {
    return;
  }
  if (exactConsumeTransferableFdForCurrentPrincipal(fd)) {
    return;
  }
  throw facebook::jsi::JSError(runtime, std::string(syscall) + ": Permission denied");
}

int registerSocketHandle(int fd, const std::string& capability, uint64_t owner = currentPrincipalId()) {
  std::lock_guard<std::mutex> lock(g_socket_mutex);
  int handle = g_next_socket_handle++;
  SocketEntry entry;
  entry.fd = fd;
  entry.identity = g_next_socket_identity++;
  captureSocketFdIdentity(entry);
  entry.runtimeNonce = exactCurrentRuntimeNonce();
  entry.owner = owner;
  entry.capability = capability;
  g_socket_handles[handle] = std::move(entry);
  return handle;
}

int registerTypedConnectHandle(
    int fd,
    uint64_t identity,
    uint64_t owner,
    const std::string& host,
    uint16_t port,
    std::string candidates,
    std::string selected,
    std::string peer,
    std::string connectionId) {
  std::lock_guard<std::mutex> lock(g_socket_mutex);
  int handle = g_next_socket_handle++;
  SocketEntry entry;
  entry.fd = fd;
  entry.identity = identity;
  captureSocketFdIdentity(entry);
  entry.runtimeNonce = exactCurrentRuntimeNonce();
  entry.owner = owner;
  entry.typedConnect = true;
  entry.typedHost = host;
  entry.typedPort = port;
  entry.typedCandidates = std::move(candidates);
  entry.typedSelected = std::move(selected);
  entry.typedPeer = std::move(peer);
  entry.typedConnectionId = std::move(connectionId);
  g_socket_handles[handle] = std::move(entry);
  return handle;
}

int registerTypedPendingConnectHandle(
    int fd,
    uint64_t owner,
    const std::string& host,
    uint16_t port,
    std::string candidates,
    std::string selected) {
  std::lock_guard<std::mutex> lock(g_socket_mutex);
  int handle = g_next_socket_handle++;
  SocketEntry entry;
  entry.fd = fd;
  entry.identity = g_next_socket_identity++;
  captureSocketFdIdentity(entry);
  entry.runtimeNonce = exactCurrentRuntimeNonce();
  entry.owner = owner;
  entry.typedConnect = true;
  entry.typedPending = true;
  entry.typedHost = host;
  entry.typedPort = port;
  entry.typedCandidates = std::move(candidates);
  entry.typedSelected = std::move(selected);
  g_socket_handles[handle] = std::move(entry);
  return handle;
}

int registerTypedListenHandle(
    int fd,
    uint64_t identity,
    uint64_t owner,
    uint32_t operationKind,
    std::string host,
    uint16_t port,
    bool dualStack,
    std::string boundAddress,
    uint16_t boundPort,
    std::string listenerId,
    std::string acceptedAddress = {},
    uint16_t acceptedPort = 0) {
  std::lock_guard<std::mutex> lock(g_socket_mutex);
  int handle = g_next_socket_handle++;
  SocketEntry entry;
  entry.fd = fd;
  entry.identity = identity;
  captureSocketFdIdentity(entry);
  entry.runtimeNonce = exactCurrentRuntimeNonce();
  entry.owner = owner;
  entry.typedListen = true;
  entry.typedListenOperationKind = operationKind;
  entry.typedListenHost = std::move(host);
  entry.typedListenPort = port;
  entry.typedListenDualStack = dualStack;
  entry.typedListenBoundAddress = std::move(boundAddress);
  entry.typedListenBoundPort = boundPort;
  entry.typedListenerId = std::move(listenerId);
  entry.typedAcceptedAddress = std::move(acceptedAddress);
  entry.typedAcceptedPort = acceptedPort;
  g_socket_handles[handle] = std::move(entry);
  return handle;
}

uint64_t reserveSocketIdentity() {
  std::lock_guard<std::mutex> lock(g_socket_mutex);
  return g_next_socket_identity++;
}

bool authorizeTypedNetwork(
    uint64_t principal,
    uint32_t networkKind,
    const std::string& host,
    uint16_t port,
    uint32_t stage,
    const std::string& candidates,
    const char* selected,
    const char* peer,
    const char* connectionId) {
  auto principals = exactCollectTypedPrincipalStack();
  return ex_host_authorize_typed_network_stack(
             principal, principals.data(), principals.size(), networkKind, host.c_str(),
             port, stage, candidates.c_str(), selected, peer, connectionId,
             UINT64_MAX) == 1;
}

bool authorizeTypedTcp(
    uint64_t principal,
    const std::string& host,
    uint16_t port,
    uint32_t stage,
    const std::string& candidates,
    const char* selected,
    const char* peer,
    const char* connectionId) {
  return authorizeTypedNetwork(
      principal, 2, host, port, stage, candidates, selected, peer,
      connectionId);
}

bool authorizeTypedListen(
    uint64_t principal,
    uint32_t operationKind,
    const std::string& host,
    uint16_t port,
    bool dualStack,
    uint32_t stage,
    const std::string& boundAddress,
    uint16_t boundPort,
    const std::string& listenerId,
    const std::string& acceptedAddress,
    uint16_t acceptedPort) {
  auto principals = exactCollectTypedPrincipalStack();
  return ex_host_authorize_typed_listen_stack(
             principal, principals.data(), principals.size(), operationKind,
             host.c_str(), port, dualStack ? 1 : 0, stage,
             boundAddress.empty() ? nullptr : boundAddress.c_str(), boundPort,
             listenerId.empty() ? nullptr : listenerId.c_str(),
             acceptedAddress.empty() ? nullptr : acceptedAddress.c_str(),
             acceptedPort) == 1;
}

bool authorizeTypedListenEntry(const SocketEntry& entry) {
  const bool accepted = !entry.typedAcceptedAddress.empty();
  return authorizeTypedListen(
      entry.owner, entry.typedListenOperationKind, entry.typedListenHost,
      entry.typedListenPort, entry.typedListenDualStack,
      accepted ? 4 : 2, entry.typedListenBoundAddress,
      entry.typedListenBoundPort, entry.typedListenerId,
      entry.typedAcceptedAddress, entry.typedAcceptedPort);
}

struct NetworkAuthorizationGenerations {
  uint64_t negative = 0;
  uint64_t dynamic = 0;
  uint64_t handle = 0;

  bool operator==(const NetworkAuthorizationGenerations& other) const {
    return negative == other.negative && dynamic == other.dynamic &&
        handle == other.handle;
  }
};

bool readNetworkAuthorizationGenerations(
    NetworkAuthorizationGenerations& generations) {
  return ex_host_typed_generations(
             &generations.negative, &generations.dynamic,
             &generations.handle) == 1;
}

std::vector<uint64_t> collectCanonicalTypedPrincipalStack() {
  auto principals = exactCollectTypedPrincipalStack();
  std::sort(principals.begin(), principals.end());
  principals.erase(
      std::unique(principals.begin(), principals.end()), principals.end());
  return principals;
}

std::optional<std::string> socketPeerText(int fd);

struct LockedSocketIo {
  std::unique_lock<std::mutex> registryLock;
  int fd = -1;

  LockedSocketIo(std::unique_lock<std::mutex> lock, int socketFd)
      : registryLock(std::move(lock)), fd(socketFd) {}
};

LockedSocketIo requireSocketIo(
    facebook::jsi::Runtime& runtime,
    int handle,
    const char* syscall) {
  NetworkAuthorizationGenerations observedGenerations;
  const bool haveGenerations =
      ex_host_is_armed() == 1 &&
      readNetworkAuthorizationGenerations(observedGenerations);
  std::vector<uint64_t> principals = haveGenerations
      ? collectCanonicalTypedPrincipalStack()
      : std::vector<uint64_t>();

  std::unique_lock<std::mutex> lock(g_socket_mutex);
  auto live = g_socket_handles.find(handle);
  if (live == g_socket_handles.end()) {
    throw facebook::jsi::JSError(runtime, std::string(syscall) + ": invalid handle");
  }
  SocketEntry& entry = live->second;
  if (!socketFdIdentityMatches(entry)) {
    g_socket_handles.erase(live);
    throw facebook::jsi::JSError(runtime, std::string(syscall) + ": stale handle");
  }
  if (entry.runtimeNonce != exactCurrentRuntimeNonce()) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  if (entry.owner != currentPrincipalId()) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  if (isAllowAll()) return LockedSocketIo(std::move(lock), entry.fd);
  if (entry.typedListen) {
    if (!authorizeTypedListenEntry(entry)) {
      throw facebook::jsi::JSError(runtime, "Permission denied");
    }
    return LockedSocketIo(std::move(lock), entry.fd);
  }
  if (!entry.typedConnect) {
    if (!entry.capability.empty() && !checkCapability(entry.capability)) {
      throw facebook::jsi::JSError(runtime, "Permission denied");
    }
    return LockedSocketIo(std::move(lock), entry.fd);
  }
  if (entry.typedPending || !haveGenerations) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }

  // @ref LLP 0021#handles-dynamic-authority-and-generations — the hot TCP
  // path reuses a peer-bound decision only for this registry identity, exact
  // principal set, and unchanged negative/dynamic/handle generations.
  if (entry.typedAuthorizationGenerationsInitialized &&
      entry.typedNegativeGeneration == observedGenerations.negative &&
      entry.typedDynamicGeneration == observedGenerations.dynamic &&
      entry.typedHandleGeneration == observedGenerations.handle &&
      entry.typedAuthorizationPrincipals == principals) {
    return LockedSocketIo(std::move(lock), entry.fd);
  }

  // A TCP peer is immutable after connect. Probe it when establishing or
  // renewing the generation lease, then pin the map entry while the I/O syscall
  // runs. This removes per-I/O SocketEntry string/vector copies and
  // getpeername calls without allowing close/fd reuse to race the syscall.
  auto actualPeer = socketPeerText(entry.fd);
  if (!actualPeer || *actualPeer != entry.typedPeer) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  const int fd = entry.fd;
  const uint64_t identity = entry.identity;
  const uint64_t owner = entry.owner;
  const std::string typedHost = entry.typedHost;
  const uint16_t typedPort = entry.typedPort;
  const std::string typedCandidates = entry.typedCandidates;
  const std::string typedSelected = entry.typedSelected;
  const std::string typedConnectionId = entry.typedConnectionId;
  lock.unlock();

  for (size_t attempt = 0; attempt < 3; ++attempt) {
    NetworkAuthorizationGenerations before;
    NetworkAuthorizationGenerations after;
    if (!readNetworkAuthorizationGenerations(before) ||
        !authorizeTypedTcp(
            owner, typedHost, typedPort, 4, typedCandidates,
            typedSelected.c_str(), actualPeer->c_str(),
            typedConnectionId.c_str()) ||
        !readNetworkAuthorizationGenerations(after)) {
      throw facebook::jsi::JSError(runtime, "Permission denied");
    }
    if (!(before == after)) continue;

    lock.lock();
    auto current = g_socket_handles.find(handle);
    if (current == g_socket_handles.end() ||
        current->second.identity != identity || current->second.fd != fd ||
        current->second.owner != owner ||
        current->second.runtimeNonce != exactCurrentRuntimeNonce() ||
        !socketFdIdentityMatches(current->second) ||
        current->second.typedPeer != *actualPeer ||
        current->second.typedConnectionId != typedConnectionId) {
      throw facebook::jsi::JSError(runtime, "Permission denied");
    }
    current->second.typedAuthorizationGenerationsInitialized = true;
    current->second.typedNegativeGeneration = after.negative;
    current->second.typedDynamicGeneration = after.dynamic;
    current->second.typedHandleGeneration = after.handle;
    current->second.typedAuthorizationPrincipals = principals;
    return LockedSocketIo(std::move(lock), fd);
  }
  throw facebook::jsi::JSError(runtime, "Permission denied");
}

LockedSocketIo requireTypedUdpSendIo(
    facebook::jsi::Runtime& runtime,
    int handle,
    const std::string& host,
    uint16_t port) {
  NetworkAuthorizationGenerations observedGenerations;
  if (!readNetworkAuthorizationGenerations(observedGenerations)) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  auto principals = collectCanonicalTypedPrincipalStack();

  std::unique_lock<std::mutex> lock(g_socket_mutex);
  auto live = g_socket_handles.find(handle);
  if (live == g_socket_handles.end()) {
    throw facebook::jsi::JSError(runtime, "__exactUdpSend: invalid handle");
  }
  SocketEntry& entry = live->second;
  if (!socketFdIdentityMatches(entry)) {
    g_socket_handles.erase(live);
    throw facebook::jsi::JSError(runtime, "__exactUdpSend: stale handle");
  }
  if (entry.runtimeNonce != exactCurrentRuntimeNonce() ||
      entry.owner != currentPrincipalId()) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }

  // @ref LLP 0021#handles-dynamic-authority-and-generations — a UDP lease is
  // exact to socket identity, literal destination, principal set, and all
  // mutable authority generations. A different endpoint or any revocation
  // re-enters the complete requested/candidate/commit decision.
  if (entry.typedUdpAuthorizationGenerationsInitialized &&
      entry.typedUdpHost == host && entry.typedUdpPort == port &&
      entry.typedUdpNegativeGeneration == observedGenerations.negative &&
      entry.typedUdpDynamicGeneration == observedGenerations.dynamic &&
      entry.typedUdpHandleGeneration == observedGenerations.handle &&
      entry.typedUdpAuthorizationPrincipals == principals) {
    return LockedSocketIo(std::move(lock), entry.fd);
  }

  const int fd = entry.fd;
  const uint64_t identity = entry.identity;
  const uint64_t owner = entry.owner;
  const uint64_t runtimeNonce = entry.runtimeNonce;
  const std::string connectionId =
      "udp:" + std::to_string(runtimeNonce) + ":" +
      std::to_string(identity) + ":" + std::to_string(fd) + ":" + host +
      ":" + std::to_string(port);
  lock.unlock();

  for (size_t attempt = 0; attempt < 3; ++attempt) {
    NetworkAuthorizationGenerations before;
    NetworkAuthorizationGenerations after;
    if (!readNetworkAuthorizationGenerations(before) ||
        ex_host_authorize_typed_udp_datagram_stack(
            owner, principals.data(), principals.size(), host.c_str(), port,
            connectionId.c_str()) != 1 ||
        !readNetworkAuthorizationGenerations(after)) {
      throw facebook::jsi::JSError(runtime, "Permission denied");
    }
    if (!(before == after)) continue;

    lock.lock();
    auto current = g_socket_handles.find(handle);
    if (current == g_socket_handles.end() ||
        current->second.identity != identity || current->second.fd != fd ||
        current->second.owner != owner ||
        current->second.runtimeNonce != runtimeNonce ||
        !socketFdIdentityMatches(current->second)) {
      throw facebook::jsi::JSError(runtime, "Permission denied");
    }
    current->second.typedUdpAuthorizationGenerationsInitialized = true;
    current->second.typedUdpHost = host;
    current->second.typedUdpPort = port;
    current->second.typedUdpNegativeGeneration = after.negative;
    current->second.typedUdpDynamicGeneration = after.dynamic;
    current->second.typedUdpHandleGeneration = after.handle;
    current->second.typedUdpAuthorizationPrincipals = principals;
    return LockedSocketIo(std::move(lock), fd);
  }
  throw facebook::jsi::JSError(runtime, "Permission denied");
}

bool authorizeTypedTcpWithLease(
    int handle,
    SocketEntry& entry,
    const std::string& actualPeer) {
  NetworkAuthorizationGenerations current;
  if (!readNetworkAuthorizationGenerations(current)) return false;
  auto principals = collectCanonicalTypedPrincipalStack();
  if (entry.typedAuthorizationGenerationsInitialized &&
      entry.typedNegativeGeneration == current.negative &&
      entry.typedDynamicGeneration == current.dynamic &&
      entry.typedHandleGeneration == current.handle &&
      entry.typedAuthorizationPrincipals == principals) {
    return true;
  }

  for (size_t attempt = 0; attempt < 3; ++attempt) {
    NetworkAuthorizationGenerations before;
    NetworkAuthorizationGenerations after;
    if (!readNetworkAuthorizationGenerations(before) ||
        !authorizeTypedTcp(
            entry.owner, entry.typedHost, entry.typedPort, 4,
            entry.typedCandidates, entry.typedSelected.c_str(),
            actualPeer.c_str(), entry.typedConnectionId.c_str()) ||
        !readNetworkAuthorizationGenerations(after)) {
      return false;
    }
    if (!(before == after)) continue;

    std::lock_guard<std::mutex> lock(g_socket_mutex);
    auto live = g_socket_handles.find(handle);
    if (live == g_socket_handles.end() ||
        live->second.identity != entry.identity ||
        live->second.fd != entry.fd ||
        live->second.owner != entry.owner ||
        !socketFdIdentityMatches(live->second) ||
        live->second.typedConnectionId != entry.typedConnectionId) {
      return false;
    }
    live->second.typedAuthorizationGenerationsInitialized = true;
    live->second.typedNegativeGeneration = after.negative;
    live->second.typedDynamicGeneration = after.dynamic;
    live->second.typedHandleGeneration = after.handle;
    live->second.typedAuthorizationPrincipals = principals;
    entry = live->second;
    return true;
  }
  return false;
}

bool isIpv4MappedAddress(const struct sockaddr* address) {
  if (address == nullptr || address->sa_family != AF_INET6) return false;
  const auto* ipv6 = reinterpret_cast<const struct sockaddr_in6*>(address);
  return IN6_IS_ADDR_V4MAPPED(&ipv6->sin6_addr);
}

bool isIpv4MappedLiteral(const std::string& host) {
  struct in6_addr address = {};
  return ::inet_pton(AF_INET6, host.c_str(), &address) == 1 &&
      IN6_IS_ADDR_V4MAPPED(&address);
}

std::optional<std::string> addressText(const struct sockaddr* address) {
  if (address == nullptr) return std::nullopt;
  char text[INET6_ADDRSTRLEN] = {};
  const void* source = nullptr;
  int family = address->sa_family;
  struct in_addr mappedIpv4 = {};
  if (family == AF_INET) {
    source = &reinterpret_cast<const struct sockaddr_in*>(address)->sin_addr;
  } else if (family == AF_INET6) {
    const auto* ipv6 = reinterpret_cast<const struct sockaddr_in6*>(address);
    if (isIpv4MappedAddress(address)) {
      std::memcpy(&mappedIpv4, &ipv6->sin6_addr.s6_addr[12], sizeof(mappedIpv4));
      family = AF_INET;
      source = &mappedIpv4;
    } else {
      source = &ipv6->sin6_addr;
    }
  } else {
    return std::nullopt;
  }
  if (::inet_ntop(family, source, text, sizeof(text)) == nullptr) {
    return std::nullopt;
  }
  return std::string(text);
}

std::optional<std::string> socketPeerText(int fd) {
  struct sockaddr_storage address = {};
  socklen_t length = sizeof(address);
  if (::getpeername(fd, reinterpret_cast<struct sockaddr*>(&address), &length) != 0) {
    return std::nullopt;
  }
  return addressText(reinterpret_cast<const struct sockaddr*>(&address));
}

std::optional<std::string> socketAddressJson(const struct sockaddr* address) {
  auto text = addressText(address);
  if (!text) return std::nullopt;
  int port = 0;
  if (address->sa_family == AF_INET) {
    port = ntohs(reinterpret_cast<const struct sockaddr_in*>(address)->sin_port);
  } else if (address->sa_family == AF_INET6) {
    port = ntohs(reinterpret_cast<const struct sockaddr_in6*>(address)->sin6_port);
  } else {
    return std::nullopt;
  }
  const char* family =
      address->sa_family == AF_INET || isIpv4MappedAddress(address) ? "IPv4" : "IPv6";
  return "{\"address\":\"" + *text + "\",\"port\":" + std::to_string(port) +
      ",\"family\":\"" + family + "\"}";
}

std::string canonicalCandidateJson(struct addrinfo* result) {
  std::vector<std::string> candidates;
  for (auto* current = result; current != nullptr; current = current->ai_next) {
    auto text = addressText(current->ai_addr);
    if (text) candidates.push_back(std::move(*text));
  }
  // IpAddress is a transparent JSON string, so ASCII lexical order is its JCS
  // semantic-set order. Keep the engine and Rust occurrence validator exact.
  std::sort(candidates.begin(), candidates.end());
  candidates.erase(std::unique(candidates.begin(), candidates.end()), candidates.end());
  std::string json = "[";
  for (size_t index = 0; index < candidates.size(); ++index) {
    if (index != 0) json += ',';
    json += '"' + candidates[index] + '"';
  }
  json += ']';
  return json;
}

// @ref LLP 0013#policy — (ENG-22819) — `requireCapability` is set by authority-bearing operations
// (UDP recv / address / getFd). A socket handle registered with an empty
// capability carries no stored network authority of its own; that is legitimate
// only for principals trusted to hold raw sockets (root / runtime). A datagram
// send is gated per-message against `network:connect` and takes the handle with
// `requireCapability=false`, so a connect-only UDP socket can still send without
// silently acquiring the receive/introspection authority of a listening socket.
SocketEntry requireSocketHandle(
    facebook::jsi::Runtime& runtime,
    int handle,
    const char* syscall,
    bool requireCapability = false,
    bool allowPending = false,
    bool requireLiveAuthority = true) {
  SocketEntry entry;
  {
    std::lock_guard<std::mutex> lock(g_socket_mutex);
    auto it = g_socket_handles.find(handle);
    if (it == g_socket_handles.end()) {
      throw facebook::jsi::JSError(runtime, std::string(syscall) + ": invalid handle");
    }
    if (!socketFdIdentityMatches(it->second)) {
      g_socket_handles.erase(it);
      throw facebook::jsi::JSError(runtime, std::string(syscall) + ": stale handle");
    }
    entry = it->second;
  }
  if (entry.runtimeNonce != exactCurrentRuntimeNonce()) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  if (entry.owner != currentPrincipalId()) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  if (!isAllowAll()) {
    if (!requireLiveAuthority) {
      return entry;
    }
    if (entry.typedConnect) {
      if (entry.typedPending) {
        if (allowPending) return entry;
        throw facebook::jsi::JSError(runtime, "TCP connection is still pending");
      }
      auto actualPeer = socketPeerText(entry.fd);
      if (!actualPeer || *actualPeer != entry.typedPeer ||
          !authorizeTypedTcpWithLease(handle, entry, *actualPeer)) {
        throw facebook::jsi::JSError(runtime, "Permission denied");
      }
    } else if (entry.typedListen) {
      if (!authorizeTypedListenEntry(entry)) {
        throw facebook::jsi::JSError(runtime, "Permission denied");
      }
    } else if (entry.capability.empty()) {
      if (requireCapability && !principalMayAdoptRawSocket(currentPrincipalId())) {
        throw facebook::jsi::JSError(runtime, "Permission denied");
      }
    } else if (!checkCapability(entry.capability)) {
      throw facebook::jsi::JSError(runtime, "Permission denied");
    }
  }
  return entry;
}

bool trySocketHandle(
    facebook::jsi::Runtime& runtime,
    int handle,
    const char* syscall,
    SocketEntry& entry,
    bool requireCapability = false,
    bool requireLiveAuthority = true) {
  try {
    entry = requireSocketHandle(
        runtime, handle, syscall, requireCapability, false, requireLiveAuthority);
    return true;
  } catch (const facebook::jsi::JSError&) {
    return false;
  }
}

int takeSocketFd(facebook::jsi::Runtime& runtime, int handle, const char* syscall) {
  // @ref LLP 0021#handles-dynamic-authority-and-generations — releasing an
  // owned handle cannot widen authority and must remain possible after its
  // positive grant is revoked.
  SocketEntry entry =
      requireSocketHandle(runtime, handle, syscall, false, true, false);
  std::lock_guard<std::mutex> lock(g_socket_mutex);
  auto it = g_socket_handles.find(handle);
  if (it == g_socket_handles.end()) {
    return -1;
  }
  if (it->second.runtimeNonce != exactCurrentRuntimeNonce() ||
      it->second.owner != entry.owner) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  if (!socketFdIdentityMatches(it->second)) {
    g_socket_handles.erase(it);
    throw facebook::jsi::JSError(runtime, std::string(syscall) + ": stale handle");
  }
  int fd = it->second.fd;
  g_socket_handles.erase(it);
  return fd;
}

void commitTypedPendingSocket(
    facebook::jsi::Runtime& runtime,
    int handle,
    const SocketEntry& pending,
    const std::string& peer) {
  std::string connectionId =
      "tcp:" + std::to_string(pending.runtimeNonce) + ":" +
      std::to_string(pending.identity) + ":" + std::to_string(pending.fd);
  if (peer != pending.typedSelected ||
      !authorizeTypedTcp(
          pending.owner, pending.typedHost, pending.typedPort, 2,
          pending.typedCandidates, pending.typedSelected.c_str(), peer.c_str(),
          connectionId.c_str())) {
    throw facebook::jsi::JSError(runtime, "Permission denied");
  }
  std::lock_guard<std::mutex> lock(g_socket_mutex);
  auto current = g_socket_handles.find(handle);
  if (current == g_socket_handles.end() ||
      current->second.identity != pending.identity ||
      current->second.fd != pending.fd ||
      current->second.runtimeNonce != exactCurrentRuntimeNonce() ||
      current->second.owner != pending.owner ||
      !socketFdIdentityMatches(current->second) ||
      !current->second.typedPending) {
    throw facebook::jsi::JSError(runtime, "TCP pending handle changed before commit");
  }
  current->second.typedPending = false;
  current->second.typedPeer = peer;
  current->second.typedConnectionId = std::move(connectionId);
}

void setSocketCapability(
    facebook::jsi::Runtime& runtime,
    int handle,
    const std::string& capability,
    const char* syscall) {
  SocketEntry entry = requireSocketHandle(runtime, handle, syscall);
  std::lock_guard<std::mutex> lock(g_socket_mutex);
  auto it = g_socket_handles.find(handle);
  if (it != g_socket_handles.end() &&
      it->second.runtimeNonce == exactCurrentRuntimeNonce() &&
      it->second.owner == entry.owner) {
    it->second.capability = capability;
  }
}

} // namespace

void exactCleanupRuntimeSockets(uint64_t runtimeNonce) {
  cleanupRuntimeSockets(runtimeNonce);
  cleanupRuntimeNetOwnerStamps(runtimeNonce);
}

void installNetOwnerHostFunction(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  // A retained JS Socket or WebSocket needs an owner identity before it has a
  // native descriptor (notably while connect/DNS is pending). The stamp is
  // opaque, random, runtime-bound, principal-bound, and shared by that
  // principal; it carries no positive network authority and allocates no
  // per-wrapper native resource. Passing an optional socket handle also proves
  // adopted-handle alignment without requiring its live capability grant.
  auto netOwnerFn = facebook::jsi::Function::createFromHostFunction(
      rt, facebook::jsi::PropNameID::forAscii(rt, "__exactNetOwner"), 3,
      [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
         const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
        if (count < 1 || !args[0].isString()) {
          throw facebook::jsi::JSError(runtime, "__exactNetOwner: action required");
        }
        const std::string action = args[0].asString(runtime).utf8(runtime);
        if (action == "new") {
          const uint64_t stamp = netOwnerStampForCurrentPrincipal();
          if (stamp == 0) {
            throw facebook::jsi::JSError(
                runtime, "__exactNetOwner: stamp allocation failed");
          }
          return facebook::jsi::Value(static_cast<double>(stamp));
        }
        if (action != "assert" || count < 2) {
          throw facebook::jsi::JSError(
              runtime, "__exactNetOwner: unsupported action");
        }
        requireNetOwnerStamp(runtime, args[1]);
        if (count > 2 && !args[2].isUndefined() && !args[2].isNull()) {
          requireSocketHandle(
              runtime, requireNetOwnerSocketHandle(runtime, args[2]),
              "__exactNetOwner", false, true, false);
        }
        return facebook::jsi::Value::undefined();
      });
  rt.global().setProperty(rt, "__exactNetOwner", std::move(netOwnerFn));
  // @ref LLP 0046#34-step-0-the-premise-is-false-the-fix-is-four-lines — the
  // source walker may credit this captured terminal only while it is immutable.
  sealGlobalHostFunction(rt, "__exactNetOwner");
}

void installNetHostFunctions(ExactHermesRuntime* handle) {
  auto& rt = *handle->runtime;
  {
    // __exactTcpConnect(host, port, localAddress?, localPort?) -> handle or throws
    auto tcpConnectFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpConnect"), 4,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 2 || !args[0].isString() || !args[1].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactTcpConnect: host (string) and port (number) required");
          }
          std::string host = args[0].toString(runtime).utf8(runtime);
          int port = static_cast<int>(args[1].asNumber());
          if (port <= 0 || port > 65535) {
            throw facebook::jsi::JSError(runtime, "__exactTcpConnect: port out of range");
          }
          if (isIpv4MappedLiteral(host)) {
            throw facebook::jsi::JSError(
                runtime,
                "__exactTcpConnect: IPv4-mapped IPv6 literals are not canonical; use IPv4");
          }
          bool hasLocalAddress = count > 2 && !args[2].isUndefined() && !args[2].isNull();
          bool hasLocalPort = count > 3 && !args[3].isUndefined() && !args[3].isNull();
          std::string localAddress;
          if (hasLocalAddress) {
            if (!args[2].isString()) {
              throw facebook::jsi::JSError(runtime, "__exactTcpConnect: localAddress must be a string");
            }
            localAddress = args[2].toString(runtime).utf8(runtime);
            if (isIpv4MappedLiteral(localAddress)) {
              throw facebook::jsi::JSError(
                  runtime,
                  "__exactTcpConnect: mapped localAddress is not canonical; use IPv4");
            }
          }
          int localPort = 0;
          if (hasLocalPort) {
            if (!args[3].isNumber()) {
              throw facebook::jsi::JSError(runtime, "__exactTcpConnect: localPort must be a number");
            }
            localPort = static_cast<int>(args[3].asNumber());
          }
          // @ref LLP 0013#policy — loading node:net is only import authority;
          // opening a TCP connection is a host-boundary operation.
          std::string connectCapability =
              networkEndpointCapability("network:connect", host, port);
          bool armed = ex_host_is_armed() == 1;
          auto principal = currentPrincipalId();
          if (armed) {
            // @ref LLP 0021#wp6--convert-network-effects-and-protected-peers — Authorize resolution candidates and commit the actual connected peer, not only the requested hostname.
            if (hasLocalAddress || hasLocalPort) {
              throw facebook::jsi::JSError(
                  runtime, "local TCP bind options are closed under armed startup");
            }
            struct in_addr ipv4 = {};
            struct in6_addr ipv6 = {};
            std::string requestedCandidates = "[]";
            if (::inet_pton(AF_INET, host.c_str(), &ipv4) == 1 ||
                ::inet_pton(AF_INET6, host.c_str(), &ipv6) == 1) {
              requestedCandidates = "[\"" + host + "\"]";
            }
            if (!authorizeTypedTcp(
                    principal, host, static_cast<uint16_t>(port), 0,
                    requestedCandidates, nullptr, nullptr, nullptr)) {
              throw facebook::jsi::JSError(runtime, "Permission denied");
            }
          } else {
            requireNetworkCapability(runtime, connectCapability, "network:connect");
          }
          struct addrinfo hints{}, *result = nullptr;
          hints.ai_family = AF_UNSPEC;
          hints.ai_socktype = SOCK_STREAM;
          hints.ai_protocol = IPPROTO_TCP;
          std::string portStr = std::to_string(port);
          int gai_err = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &result);
          if (gai_err != 0) {
            throw facebook::jsi::JSError(runtime,
                ("getaddrinfo failed for " + host + ":" + portStr + ": " + gai_strerror(gai_err)).c_str());
          }
          std::string candidatesJson = canonicalCandidateJson(result);
          if (candidatesJson == "[]") {
            freeaddrinfo(result);
            throw facebook::jsi::JSError(runtime, "resolver returned no usable TCP candidates");
          }
          int fd = -1;
          std::string selectedCandidate;
          for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
            auto candidate = addressText(rp->ai_addr);
            if (!candidate) continue;
            if (armed && !authorizeTypedTcp(
                    principal, host, static_cast<uint16_t>(port), 1,
                    candidatesJson, candidate->c_str(), nullptr, nullptr)) {
              continue;
            }
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd == -1) continue;
            if (hasLocalAddress || hasLocalPort) {
              struct addrinfo bindHints{}, *bindResult = nullptr;
              bindHints.ai_family = rp->ai_family;
              bindHints.ai_socktype = rp->ai_socktype;
              bindHints.ai_protocol = rp->ai_protocol;
              bindHints.ai_flags = AI_PASSIVE;
              std::string localPortStr = std::to_string(localPort);
              const char* bindNode = hasLocalAddress ? localAddress.c_str() : nullptr;
              int bindGaiErr = getaddrinfo(bindNode, localPortStr.c_str(), &bindHints, &bindResult);
              if (bindGaiErr != 0) {
                ::close(fd);
                fd = -1;
                continue;
              }
              bool bound = false;
              int bindErrno = 0;
              for (struct addrinfo* bp = bindResult; bp != nullptr; bp = bp->ai_next) {
                if (::bind(fd, bp->ai_addr, bp->ai_addrlen) == 0) {
                  bound = true;
                  break;
                }
                bindErrno = errno;
              }
              freeaddrinfo(bindResult);
              if (!bound) {
                ::close(fd);
                freeaddrinfo(result);
                throw facebook::jsi::JSError(runtime,
                    ("bind() failed: " + std::string(strerror(bindErrno))).c_str());
              }
            }
            if (::connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
              selectedCandidate = std::move(*candidate);
              break;
            }
            ::close(fd);
            fd = -1;
          }
          freeaddrinfo(result);
          if (fd == -1) {
            throw facebook::jsi::JSError(runtime,
                ("connect failed for " + host + ":" + portStr + ": " + strerror(errno)).c_str());
          }
          if (armed) {
            auto peer = socketPeerText(fd);
            uint64_t socketIdentity = reserveSocketIdentity();
            std::string connectionId =
                "tcp:" + std::to_string(exactCurrentRuntimeNonce()) + ":" +
                std::to_string(socketIdentity) + ":" + std::to_string(fd);
            if (!peer || *peer != selectedCandidate ||
                !authorizeTypedTcp(
                    principal, host, static_cast<uint16_t>(port), 2,
                    candidatesJson, selectedCandidate.c_str(),
                    peer ? peer->c_str() : nullptr, connectionId.c_str())) {
              ::close(fd);
              throw facebook::jsi::JSError(runtime, "Permission denied");
            }
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            int socketHandle = registerTypedConnectHandle(
                fd, socketIdentity, principal, host, static_cast<uint16_t>(port),
                std::move(candidatesJson), std::move(selectedCandidate),
                std::move(*peer), std::move(connectionId));
            return facebook::jsi::Value(socketHandle);
          }
          int flags = fcntl(fd, F_GETFL, 0);
          if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
          int handle = registerSocketHandle(fd, connectCapability);
          return facebook::jsi::Value(handle);
        });
    rt.global().setProperty(rt, "__exactTcpConnect", std::move(tcpConnectFn));

    // __exactTcpConnectStart(host, port, localAddress?, localPort?) -> handle or throws
    // Non-blocking connect (ENG-22994). Unlike __exactTcpConnect, which does a
    // BLOCKING ::connect on the JS thread (freezing every timer/socket/server
    // for the OS connect timeout on a slow/blackholed host), this sets
    // O_NONBLOCK *before* ::connect, accepts EINPROGRESS, and returns a handle
    // immediately. Completion is reported asynchronously via
    // __exactTcpConnectPoll, driven by the same setTimeout poll loop that
    // already services reads. getaddrinfo stays synchronous here: callers
    // resolve hostnames to IP literals before connecting (async DNS is tracked
    // separately in ENG-22995), so it returns without a network round-trip.
    auto tcpConnectStartFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpConnectStart"), 4,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 2 || !args[0].isString() || !args[1].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactTcpConnectStart: host (string) and port (number) required");
          }
          std::string host = args[0].toString(runtime).utf8(runtime);
          int port = static_cast<int>(args[1].asNumber());
          if (port <= 0 || port > 65535) {
            throw facebook::jsi::JSError(runtime, "__exactTcpConnectStart: port out of range");
          }
          if (isIpv4MappedLiteral(host)) {
            throw facebook::jsi::JSError(
                runtime,
                "__exactTcpConnectStart: IPv4-mapped IPv6 literals are not canonical; use IPv4");
          }
          bool hasLocalAddress = count > 2 && !args[2].isUndefined() && !args[2].isNull();
          bool hasLocalPort = count > 3 && !args[3].isUndefined() && !args[3].isNull();
          std::string localAddress;
          if (hasLocalAddress) {
            if (!args[2].isString()) {
              throw facebook::jsi::JSError(runtime, "__exactTcpConnectStart: localAddress must be a string");
            }
            localAddress = args[2].toString(runtime).utf8(runtime);
            if (isIpv4MappedLiteral(localAddress)) {
              throw facebook::jsi::JSError(
                  runtime,
                  "__exactTcpConnectStart: mapped localAddress is not canonical; use IPv4");
            }
          }
          int localPort = 0;
          if (hasLocalPort) {
            if (!args[3].isNumber()) {
              throw facebook::jsi::JSError(runtime, "__exactTcpConnectStart: localPort must be a number");
            }
            localPort = static_cast<int>(args[3].asNumber());
          }
          // @ref LLP 0013#policy — loading node:net is only import authority;
          // opening a TCP connection is a host-boundary operation.
          std::string connectCapability =
              networkEndpointCapability("network:connect", host, port);
          bool armed = ex_host_is_armed() == 1;
          auto principal = currentPrincipalId();
          if (armed) {
            if (hasLocalAddress || hasLocalPort) {
              throw facebook::jsi::JSError(
                  runtime, "local TCP bind options are closed under armed startup");
            }
            struct in_addr ipv4 = {};
            struct in6_addr ipv6 = {};
            std::string requestedCandidates = "[]";
            if (::inet_pton(AF_INET, host.c_str(), &ipv4) == 1 ||
                ::inet_pton(AF_INET6, host.c_str(), &ipv6) == 1) {
              requestedCandidates = "[\"" + host + "\"]";
            }
            if (!authorizeTypedTcp(
                    principal, host, static_cast<uint16_t>(port), 0,
                    requestedCandidates, nullptr, nullptr, nullptr)) {
              throw facebook::jsi::JSError(runtime, "Permission denied");
            }
          } else {
            requireNetworkCapability(runtime, connectCapability, "network:connect");
          }
          struct addrinfo hints{}, *result = nullptr;
          hints.ai_family = AF_UNSPEC;
          hints.ai_socktype = SOCK_STREAM;
          hints.ai_protocol = IPPROTO_TCP;
          std::string portStr = std::to_string(port);
          int gai_err = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &result);
          if (gai_err != 0) {
            throw facebook::jsi::JSError(runtime,
                ("getaddrinfo failed for " + host + ":" + portStr + ": " + gai_strerror(gai_err)).c_str());
          }
          std::string candidatesJson = canonicalCandidateJson(result);
          if (candidatesJson == "[]") {
            freeaddrinfo(result);
            throw facebook::jsi::JSError(runtime, "resolver returned no usable TCP candidates");
          }
          int fd = -1;
          int connectErrno = 0;
          std::string selectedCandidate;
          for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
            auto candidate = addressText(rp->ai_addr);
            if (!candidate) continue;
            if (armed && !authorizeTypedTcp(
                    principal, host, static_cast<uint16_t>(port), 1,
                    candidatesJson, candidate->c_str(), nullptr, nullptr)) {
              continue;
            }
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd == -1) { connectErrno = errno; continue; }
            // Non-blocking BEFORE ::connect so the syscall returns immediately
            // (EINPROGRESS) instead of blocking the JS thread. (ENG-22994)
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            if (hasLocalAddress || hasLocalPort) {
              struct addrinfo bindHints{}, *bindResult = nullptr;
              bindHints.ai_family = rp->ai_family;
              bindHints.ai_socktype = rp->ai_socktype;
              bindHints.ai_protocol = rp->ai_protocol;
              bindHints.ai_flags = AI_PASSIVE;
              std::string localPortStr = std::to_string(localPort);
              const char* bindNode = hasLocalAddress ? localAddress.c_str() : nullptr;
              int bindGaiErr = getaddrinfo(bindNode, localPortStr.c_str(), &bindHints, &bindResult);
              if (bindGaiErr != 0) {
                ::close(fd);
                fd = -1;
                continue;
              }
              bool bound = false;
              int bindErrno = 0;
              for (struct addrinfo* bp = bindResult; bp != nullptr; bp = bp->ai_next) {
                if (::bind(fd, bp->ai_addr, bp->ai_addrlen) == 0) {
                  bound = true;
                  break;
                }
                bindErrno = errno;
              }
              freeaddrinfo(bindResult);
              if (!bound) {
                ::close(fd);
                freeaddrinfo(result);
                throw facebook::jsi::JSError(runtime,
                    ("bind() failed: " + std::string(strerror(bindErrno))).c_str());
              }
            }
            int rc = ::connect(fd, rp->ai_addr, rp->ai_addrlen);
            // rc == 0: connected immediately (e.g. localhost/AF_UNIX-fast path).
            // EINPROGRESS: handshake in flight; __exactTcpConnectPoll reports it.
            // Both are success for the async model — register and hand back the
            // handle. Any other errno means this candidate failed; try the next.
            if (rc == 0 || errno == EINPROGRESS) {
              selectedCandidate = std::move(*candidate);
              break;
            }
            connectErrno = errno;
            ::close(fd);
            fd = -1;
          }
          freeaddrinfo(result);
          if (fd == -1) {
            throw facebook::jsi::JSError(runtime,
                ("connect failed for " + host + ":" + portStr + ": " + strerror(connectErrno)).c_str());
          }
          int handle = armed
              ? registerTypedPendingConnectHandle(
                    fd, principal, host, static_cast<uint16_t>(port),
                    std::move(candidatesJson), std::move(selectedCandidate))
              : registerSocketHandle(fd, connectCapability);
          return facebook::jsi::Value(handle);
        });
    rt.global().setProperty(rt, "__exactTcpConnectStart", std::move(tcpConnectStartFn));

    // __exactTcpConnectPoll(handle) -> 0 (pending) | 1 (connected); throws on failure
    // Drives async connect completion (ENG-22994) without blocking. poll() with
    // POLLOUT and a 0ms timeout tests writability; a completed connect makes the
    // socket writable, at which point getsockopt(SO_ERROR) distinguishes success
    // (0) from failure. The thrown message carries strerror() so the JS layer
    // (_createConnectErrorFromRaw) maps it to ECONNREFUSED/ETIMEDOUT/ENETUNREACH.
    auto tcpConnectPollFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpConnectPoll"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactTcpConnectPoll: handle required");
          }
          int handle = static_cast<int>(args[0].asNumber());
          SocketEntry socket = requireSocketHandle(
              runtime, handle, "__exactTcpConnectPoll", false, true);
          int fd = socket.fd;
          struct pollfd pfd;
          pfd.fd = fd;
          pfd.events = POLLOUT;
          pfd.revents = 0;
          int pr = ::poll(&pfd, 1, 0);
          if (pr == 0) {
            return facebook::jsi::Value(0);  // handshake still in progress
          }
          if (pr < 0) {
            if (errno == EINTR || errno == EAGAIN) return facebook::jsi::Value(0);
            throw facebook::jsi::JSError(runtime,
                ("__exactTcpConnectPoll poll error: " + std::string(strerror(errno))).c_str());
          }
          int soError = 0;
          socklen_t soLen = sizeof(soError);
          if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &soLen) == -1) {
            throw facebook::jsi::JSError(runtime,
                ("__exactTcpConnectPoll getsockopt error: " + std::string(strerror(errno))).c_str());
          }
          if (soError != 0) {
            throw facebook::jsi::JSError(runtime,
                ("connect failed: " + std::string(strerror(soError))).c_str());
          }
          if (socket.typedPending) {
            auto peer = socketPeerText(fd);
            if (!peer) {
              throw facebook::jsi::JSError(
                  runtime, "connected TCP socket has no verifiable peer");
            }
            commitTypedPendingSocket(runtime, handle, socket, *peer);
          }
          return facebook::jsi::Value(1);  // connected
        });
    rt.global().setProperty(rt, "__exactTcpConnectPoll", std::move(tcpConnectPollFn));

    // __exactTcpRead(handle, maxBytes) -> Uint8Array (data), null (EOF), "" (EAGAIN)
    auto tcpReadFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpRead"), 2,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactTcpRead: handle required");
          }
          int handle = static_cast<int>(args[0].asNumber());
          int maxBytes = 65536;
          if (count > 1 && args[1].isNumber()) {
            maxBytes = static_cast<int>(args[1].asNumber());
            if (maxBytes <= 0) maxBytes = 65536;
          }
          std::vector<uint8_t> buf(maxBytes);
          auto socketIo = requireSocketIo(runtime, handle, "__exactTcpRead");
          ssize_t n = ::read(socketIo.fd, buf.data(), maxBytes);
          int readError = n < 0 ? errno : 0;
          socketIo.registryLock.unlock();
          if (n > 0) {
            buf.resize(n);
            return makeUint8Array(runtime, std::move(buf));
          } else if (n == 0) {
            return facebook::jsi::Value::null();
          } else {
            if (readError == EAGAIN || readError == EWOULDBLOCK) {
              return facebook::jsi::String::createFromUtf8(runtime, "");
            }
            throw facebook::jsi::JSError(
                runtime,
                ("__exactTcpRead error: " + std::string(strerror(readError)))
                    .c_str());
          }
        });
    rt.global().setProperty(rt, "__exactTcpRead", std::move(tcpReadFn));

    auto stringToUtf8BytesFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactStringToUtf8Bytes"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1) {
            throw facebook::jsi::JSError(runtime, "__exactStringToUtf8Bytes: string required");
          }
          std::string data = args[0].toString(runtime).utf8(runtime);
          std::vector<uint8_t> bytes(data.begin(), data.end());
          return makeUint8Array(runtime, std::move(bytes));
        });
    rt.global().setProperty(rt, "__exactStringToUtf8Bytes", std::move(stringToUtf8BytesFn));

    // __exactTcpWrite(handle, data) -> bytes written
    auto tcpWriteFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpWrite"), 2,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 2 || !args[0].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactTcpWrite: handle and data required");
          }
          int handle = static_cast<int>(args[0].asNumber());
          std::string ownedData;
          const uint8_t* data = nullptr;
          size_t length = 0;
          if (args[1].isString()) {
            ownedData = args[1].toString(runtime).utf8(runtime);
            data = reinterpret_cast<const uint8_t*>(ownedData.data());
            length = ownedData.size();
          } else if (args[1].isObject()) {
            auto obj = args[1].asObject(runtime);
            if (!extractArrayBufferView(runtime, obj, data, length)) {
              ownedData = args[1].toString(runtime).utf8(runtime);
              data = reinterpret_cast<const uint8_t*>(ownedData.data());
              length = ownedData.size();
            }
          } else {
            ownedData = args[1].toString(runtime).utf8(runtime);
            data = reinterpret_cast<const uint8_t*>(ownedData.data());
            length = ownedData.size();
          }
          auto socketIo = requireSocketIo(runtime, handle, "__exactTcpWrite");
          ssize_t written = length == 0 ? 0 : ::write(socketIo.fd, data, length);
          int writeError = written < 0 ? errno : 0;
          socketIo.registryLock.unlock();
          if (written < 0) {
            if (writeError == EAGAIN || writeError == EWOULDBLOCK) {
              return facebook::jsi::Value(0);
            }
            throw facebook::jsi::JSError(
                runtime,
                ("__exactTcpWrite error: " + std::string(strerror(writeError)))
                    .c_str());
          }
          return facebook::jsi::Value(static_cast<int>(written));
        });
    rt.global().setProperty(rt, "__exactTcpWrite", std::move(tcpWriteFn));

    // __exactTcpClose(handle) -> 0
    auto tcpCloseFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpClose"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) throw facebook::jsi::JSError(runtime, "__exactTcpClose: handle required");
          int handle = static_cast<int>(args[0].asNumber());
          int fd = takeSocketFd(runtime, handle, "__exactTcpClose");
          if (fd >= 0) ::close(fd);
          return facebook::jsi::Value(0);
        });
    rt.global().setProperty(rt, "__exactTcpClose", std::move(tcpCloseFn));

    // __exactTcpFromFd(fd) -> handle
    // Register an existing raw file descriptor as a TCP handle.
    // Used for SCM_RIGHTS: after receiving an fd via recvmsg, register it so
    // net.Socket can wrap it with full read/write/close support.
    auto tcpFromFdFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpFromFd"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactTcpFromFd: fd (number) required");
          }
          int fd = static_cast<int>(args[0].asNumber());
          if (fd < 0) {
            throw facebook::jsi::JSError(runtime, "__exactTcpFromFd: invalid fd");
          }
          requireRawSocketAdoptionAllowed(runtime, fd, "__exactTcpFromFd");
          // Set non-blocking mode
          int flags = fcntl(fd, F_GETFL, 0);
          if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
          int handle = registerSocketHandle(fd, "");
          return facebook::jsi::Value(handle);
        });
    rt.global().setProperty(rt, "__exactTcpFromFd", std::move(tcpFromFdFn));

    // __exactTcpGetFd(handle) -> raw fd
    // Get the underlying raw file descriptor for a TCP handle.
    // Used for SCM_RIGHTS: need the raw fd to send via sendmsg.
    auto tcpGetFdFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpGetFd"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) {
            return facebook::jsi::Value(-1);
          }
          int handle = static_cast<int>(args[0].asNumber());
          SocketEntry entry;
          if (!trySocketHandle(runtime, handle, "__exactTcpGetFd", entry)) {
            return facebook::jsi::Value(-1);
          }
          exactRegisterTransferableFd(entry.fd, entry.owner);
          return facebook::jsi::Value(entry.fd);
        });
    rt.global().setProperty(rt, "__exactTcpGetFd", std::move(tcpGetFdFn));

    // __exactTcpShutdown(handle, how) -> 0
    // how: 0=SHUT_RD, 1=SHUT_WR, 2=SHUT_RDWR
    auto tcpShutdownFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpShutdown"), 2,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) throw facebook::jsi::JSError(runtime, "__exactTcpShutdown: handle required");
          int handle = static_cast<int>(args[0].asNumber());
          int how = SHUT_WR;
          if (count > 1 && args[1].isNumber()) {
            int h = static_cast<int>(args[1].asNumber());
            if (h == 0) how = SHUT_RD;
            else if (h == 2) how = SHUT_RDWR;
          }
          SocketEntry entry;
          if (!trySocketHandle(
                  runtime, handle, "__exactTcpShutdown", entry, false, false)) {
            return facebook::jsi::Value(0);
          }
          int fd = entry.fd;
          ::shutdown(fd, how);
          return facebook::jsi::Value(0);
        });
    rt.global().setProperty(rt, "__exactTcpShutdown", std::move(tcpShutdownFn));

    // __exactTcpReset(handle) -> 0
    auto tcpResetFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpReset"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactTcpReset: handle required");
          }
          int handle = static_cast<int>(args[0].asNumber());
          SocketEntry entry;
          if (!trySocketHandle(
                  runtime, handle, "__exactTcpReset", entry, false, false)) {
            return facebook::jsi::Value(0);
          }
          int fd = entry.fd;
          struct linger lingerOpt;
          lingerOpt.l_onoff = 1;
          lingerOpt.l_linger = 0;
          setsockopt(fd, SOL_SOCKET, SO_LINGER, &lingerOpt, sizeof(lingerOpt));
          ::shutdown(fd, SHUT_RDWR);
          return facebook::jsi::Value(0);
        });
    rt.global().setProperty(rt, "__exactTcpReset", std::move(tcpResetFn));

    // __exactTcpSetNoDelay(handle, enable) -> 0
    auto tcpSetNoDelayFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpSetNoDelay"), 2,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) throw facebook::jsi::JSError(runtime, "__exactTcpSetNoDelay: handle required");
          int handle = static_cast<int>(args[0].asNumber());
          int enable = (count > 1 && args[1].isNumber()) ? static_cast<int>(args[1].asNumber()) : 1;
          SocketEntry entry;
          if (!trySocketHandle(runtime, handle, "__exactTcpSetNoDelay", entry)) {
            return facebook::jsi::Value(-1);
          }
          int fd = entry.fd;
          int flag = enable ? 1 : 0;
          setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
          return facebook::jsi::Value(0);
        });
    rt.global().setProperty(rt, "__exactTcpSetNoDelay", std::move(tcpSetNoDelayFn));

    // __exactTcpSetKeepAlive(handle, enable, idleSeconds) -> 0
    // idleSeconds > 0 additionally sets the probe idle interval
    // (TCP_KEEPIDLE on Linux, TCP_KEEPALIVE on Darwin) so Node's
    // setKeepAlive(enable, initialDelay) is honored instead of silently
    // using the OS default (~2h) (ENG-23456).
    auto tcpSetKeepAliveFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpSetKeepAlive"), 3,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) throw facebook::jsi::JSError(runtime, "__exactTcpSetKeepAlive: handle required");
          int handle = static_cast<int>(args[0].asNumber());
          int enable = (count > 1 && args[1].isNumber()) ? static_cast<int>(args[1].asNumber()) : 1;
          int idleSeconds = (count > 2 && args[2].isNumber()) ? static_cast<int>(args[2].asNumber()) : 0;
          SocketEntry entry;
          if (!trySocketHandle(runtime, handle, "__exactTcpSetKeepAlive", entry)) {
            return facebook::jsi::Value(-1);
          }
          int fd = entry.fd;
          int flag = enable ? 1 : 0;
          setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));
          if (flag && idleSeconds > 0) {
#if defined(TCP_KEEPIDLE)
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idleSeconds, sizeof(idleSeconds));
#elif defined(TCP_KEEPALIVE)
            setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &idleSeconds, sizeof(idleSeconds));
#endif
          }
          return facebook::jsi::Value(0);
        });
    rt.global().setProperty(rt, "__exactTcpSetKeepAlive", std::move(tcpSetKeepAliveFn));

    // __exactTcpListen(host, port, backlog, ipv6Only, reusePort) -> handle or throws
    auto tcpListenFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpListen"), 5,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          std::string host = "0.0.0.0";
          if (count > 0 && args[0].isString()) host = args[0].toString(runtime).utf8(runtime);
          int port = 0;
          if (count > 1 && args[1].isNumber()) port = static_cast<int>(args[1].asNumber());
          if (port < 0 || port > 65535) {
            throw facebook::jsi::JSError(runtime, "__exactTcpListen: port out of range");
          }
          int backlog = 128;
          if (count > 2 && args[2].isNumber()) backlog = static_cast<int>(args[2].asNumber());
          int ipv6Only = 0;
          if (count > 3 && args[3].isNumber()) ipv6Only = static_cast<int>(args[3].asNumber());
          int reusePort = 0;
          if (count > 4 && args[4].isNumber()) reusePort = static_cast<int>(args[4].asNumber());
          if (isIpv4MappedLiteral(host)) {
            throw facebook::jsi::JSError(
                runtime,
                "__exactTcpListen: IPv4-mapped IPv6 literals are not canonical; use IPv4");
          }
          // @ref LLP 0013#policy — listening/binding requires host authority,
          // independent of the builtin import allowlist. (ENG-22722)
          std::string listenCapability =
              networkEndpointCapability("network:listen", host, port);
          const bool armed = ex_host_is_armed() == 1;
          const uint64_t owner = currentPrincipalId();
          const bool dualStack = host == "::" && ipv6Only == 0;
          if (armed) {
            // The listen occurrence must name the exact requested bind before
            // getaddrinfo/bind and the exact OS-selected endpoint after bind.
            // A single descriptor cannot currently enumerate both families of
            // an implicit dual-stack wildcard bind, so keep that shape closed
            // instead of recording an incomplete occurrence.
            // @ref LLP 0021#wp6--convert-network-effects-and-protected-peers
            if (dualStack) {
              throw facebook::jsi::JSError(
                  runtime, "dual-stack wildcard listen is closed under armed startup");
            }
            if (!authorizeTypedListen(
                    owner, 0, host, static_cast<uint16_t>(port), dualStack, 0,
                    "", 0, "", "", 0)) {
              throw facebook::jsi::JSError(runtime, "Permission denied");
            }
          } else {
            requireNetworkCapability(runtime, listenCapability, "network:listen");
          }
          struct addrinfo hints{}, *result = nullptr;
          if (ipv6Only || host.find(':') != std::string::npos) {
            hints.ai_family = AF_INET6;
          } else {
            hints.ai_family = AF_UNSPEC;
          }
          hints.ai_socktype = SOCK_STREAM;
          hints.ai_protocol = IPPROTO_TCP;
          hints.ai_flags = AI_PASSIVE;
          std::string portStr = std::to_string(port);
          const char* nodeStr = host == "0.0.0.0" ? nullptr : host.c_str();
          int gai_err = getaddrinfo(nodeStr, portStr.c_str(), &hints, &result);
          if (gai_err != 0) {
            throw facebook::jsi::JSError(runtime, ("getaddrinfo failed: " + std::string(gai_strerror(gai_err))).c_str());
          }
          // @ref LLP 0008#sockets-dns-and-process — try every POSIX addrinfo candidate for robust dual-stack listen setup.
          int fd = -1;
          int saved_errno = 0;
          for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd == -1) {
              saved_errno = errno;
              continue;
            }
            if (rp->ai_family == AF_INET6) {
              int flag = ipv6Only ? 1 : 0;
              if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag)) != 0) {
                saved_errno = errno;
                ::close(fd);
                fd = -1;
                continue;
              }
            }
            int reuse = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
            if (reusePort) {
#ifdef SO_REUSEPORT
              int rp_flag = 1;
              setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &rp_flag, sizeof(rp_flag));
#endif
            }
            if (::bind(fd, rp->ai_addr, rp->ai_addrlen) == -1) {
              saved_errno = errno;
              ::close(fd);
              fd = -1;
              continue;
            }
            if (::listen(fd, backlog) == -1) {
              saved_errno = errno;
              ::close(fd);
              fd = -1;
              continue;
            }
            break;
          }
          freeaddrinfo(result);
          if (fd == -1) {
            if (saved_errno == 0) saved_errno = errno;
            throw facebook::jsi::JSError(runtime, ("listen setup failed: " + std::string(strerror(saved_errno))).c_str());
          }
          int flags = fcntl(fd, F_GETFL, 0);
          if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
          int handle = 0;
          if (armed) {
            struct sockaddr_storage bound = {};
            socklen_t boundLength = sizeof(bound);
            if (::getsockname(
                    fd, reinterpret_cast<struct sockaddr*>(&bound),
                    &boundLength) != 0) {
              int saved = errno;
              ::close(fd);
              throw facebook::jsi::JSError(
                  runtime,
                  ("getsockname failed after listen: " +
                   std::string(strerror(saved))).c_str());
            }
            auto boundAddress =
                addressText(reinterpret_cast<const struct sockaddr*>(&bound));
            uint16_t boundPort = 0;
            if (bound.ss_family == AF_INET) {
              boundPort = ntohs(reinterpret_cast<struct sockaddr_in*>(&bound)->sin_port);
            } else if (bound.ss_family == AF_INET6) {
              boundPort = ntohs(reinterpret_cast<struct sockaddr_in6*>(&bound)->sin6_port);
            }
            const uint64_t identity = reserveSocketIdentity();
            const std::string listenerId =
                "tcp-listener:" + std::to_string(exactCurrentRuntimeNonce()) +
                ":" + std::to_string(identity);
            if (!boundAddress || boundPort == 0 ||
                !authorizeTypedListen(
                    owner, 0, host, static_cast<uint16_t>(port), dualStack, 2,
                    boundAddress ? *boundAddress : "", boundPort, listenerId,
                    "", 0)) {
              ::close(fd);
              throw facebook::jsi::JSError(runtime, "Permission denied");
            }
            handle = registerTypedListenHandle(
                fd, identity, owner, 0, host, static_cast<uint16_t>(port),
                dualStack, *boundAddress, boundPort, listenerId);
          } else {
            handle = registerSocketHandle(fd, listenCapability);
          }
          return facebook::jsi::Value(handle);
        });
    rt.global().setProperty(rt, "__exactTcpListen", std::move(tcpListenFn));

    // __exactTcpAccept(handle) -> new handle or -1 (EAGAIN)
    auto tcpAcceptFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpAccept"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) throw facebook::jsi::JSError(runtime, "__exactTcpAccept: handle required");
          int handle = static_cast<int>(args[0].asNumber());
          SocketEntry listenEntry = requireSocketHandle(runtime, handle, "__exactTcpAccept");
          int listenFd = listenEntry.fd;
          struct sockaddr_storage clientAddr;
          socklen_t clientLen = sizeof(clientAddr);
          int clientFd = ::accept(listenFd, reinterpret_cast<struct sockaddr*>(&clientAddr), &clientLen);
          if (clientFd == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return facebook::jsi::Value(-1);
            throw facebook::jsi::JSError(runtime, ("__exactTcpAccept error: " + std::string(strerror(errno))).c_str());
          }
          int flags = fcntl(clientFd, F_GETFL, 0);
          if (flags != -1) fcntl(clientFd, F_SETFL, flags | O_NONBLOCK);
          int newHandle = 0;
          if (listenEntry.typedListen) {
            auto acceptedAddress = addressText(
                reinterpret_cast<const struct sockaddr*>(&clientAddr));
            uint16_t acceptedPort = 0;
            if (clientAddr.ss_family == AF_INET) {
              acceptedPort = ntohs(
                  reinterpret_cast<struct sockaddr_in*>(&clientAddr)->sin_port);
            } else if (clientAddr.ss_family == AF_INET6) {
              acceptedPort = ntohs(
                  reinterpret_cast<struct sockaddr_in6*>(&clientAddr)->sin6_port);
            }
            if (!acceptedAddress || acceptedPort == 0 ||
                !authorizeTypedListen(
                    listenEntry.owner, listenEntry.typedListenOperationKind,
                    listenEntry.typedListenHost, listenEntry.typedListenPort,
                    listenEntry.typedListenDualStack, 3,
                    listenEntry.typedListenBoundAddress,
                    listenEntry.typedListenBoundPort,
                    listenEntry.typedListenerId,
                    acceptedAddress ? *acceptedAddress : "", acceptedPort)) {
              ::close(clientFd);
              throw facebook::jsi::JSError(runtime, "Permission denied");
            }
            newHandle = registerTypedListenHandle(
                clientFd, reserveSocketIdentity(), listenEntry.owner,
                listenEntry.typedListenOperationKind,
                listenEntry.typedListenHost, listenEntry.typedListenPort,
                listenEntry.typedListenDualStack,
                listenEntry.typedListenBoundAddress,
                listenEntry.typedListenBoundPort,
                listenEntry.typedListenerId, *acceptedAddress, acceptedPort);
          } else {
            newHandle = registerSocketHandle(
                clientFd, listenEntry.capability, listenEntry.owner);
          }
          return facebook::jsi::Value(newHandle);
        });
    rt.global().setProperty(rt, "__exactTcpAccept", std::move(tcpAcceptFn));

    // __exactTcpLocalAddr(handle) -> JSON string or null
    auto tcpLocalAddrFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpLocalAddr"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) return facebook::jsi::Value::null();
          int handle = static_cast<int>(args[0].asNumber());
          SocketEntry entry;
          if (!trySocketHandle(runtime, handle, "__exactTcpLocalAddr", entry)) {
            return facebook::jsi::Value::null();
          }
          int fd = entry.fd;
          struct sockaddr_storage addr;
          socklen_t addrLen = sizeof(addr);
          if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &addrLen) == -1) return facebook::jsi::Value::null();
          auto json = socketAddressJson(reinterpret_cast<const struct sockaddr*>(&addr));
          if (!json) return facebook::jsi::Value::null();
          return facebook::jsi::String::createFromUtf8(runtime, *json);
        });
    rt.global().setProperty(rt, "__exactTcpLocalAddr", std::move(tcpLocalAddrFn));

    // __exactTcpRemoteAddr(handle) -> JSON string or null
    auto tcpRemoteAddrFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactTcpRemoteAddr"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) return facebook::jsi::Value::null();
          int handle = static_cast<int>(args[0].asNumber());
          SocketEntry entry;
          if (!trySocketHandle(runtime, handle, "__exactTcpRemoteAddr", entry)) {
            return facebook::jsi::Value::null();
          }
          int fd = entry.fd;
          struct sockaddr_storage addr;
          socklen_t addrLen = sizeof(addr);
          if (getpeername(fd, reinterpret_cast<struct sockaddr*>(&addr), &addrLen) == -1) return facebook::jsi::Value::null();
          auto json = socketAddressJson(reinterpret_cast<const struct sockaddr*>(&addr));
          if (!json) return facebook::jsi::Value::null();
          return facebook::jsi::String::createFromUtf8(runtime, *json);
        });
    rt.global().setProperty(rt, "__exactTcpRemoteAddr", std::move(tcpRemoteAddrFn));

    // ============================================================
    // Unix Domain Socket host functions
    // Reuses the native socket-handle registry so that
    // __exactTcpRead, __exactTcpWrite, __exactTcpClose work on
    // Unix socket fds too (they all use the same fd-based I/O).
    // ============================================================

    // __exactUnixConnect(path) -> handle or throws
    auto unixConnectFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactUnixConnect"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isString()) {
            throw facebook::jsi::JSError(runtime, "__exactUnixConnect: path (string) required");
          }
          std::string path = args[0].toString(runtime).utf8(runtime);
          if (path.size() >= sizeof(((struct sockaddr_un*)0)->sun_path)) {
            throw facebook::jsi::JSError(runtime, "__exactUnixConnect: path too long");
          }
          std::string localCapability = "network:local:" + path;
          requireNetworkCapability(runtime, localCapability, "network:local");
          if (!checkCapability("fs:read:" + path)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
          int fd = socket(AF_UNIX, SOCK_STREAM, 0);
          if (fd == -1) {
            throw facebook::jsi::JSError(runtime,
                ("socket(AF_UNIX) failed: " + std::string(strerror(errno))).c_str());
          }
          struct sockaddr_un addr;
          memset(&addr, 0, sizeof(addr));
          addr.sun_family = AF_UNIX;
          strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
          if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == -1) {
            int saved_errno = errno;
            ::close(fd);
            throw facebook::jsi::JSError(runtime,
                ("connect(AF_UNIX) failed for " + path + ": " + strerror(saved_errno)).c_str());
          }
          int flags = fcntl(fd, F_GETFL, 0);
          if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
          int handle = registerSocketHandle(fd, localCapability);
          return facebook::jsi::Value(handle);
        });
    rt.global().setProperty(rt, "__exactUnixConnect", std::move(unixConnectFn));

    // __exactUnixListen(path, backlog) -> handle or throws
    auto unixListenFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactUnixListen"), 2,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isString()) {
            throw facebook::jsi::JSError(runtime, "__exactUnixListen: path (string) required");
          }
          std::string path = args[0].toString(runtime).utf8(runtime);
          if (path.size() >= sizeof(((struct sockaddr_un*)0)->sun_path)) {
            throw facebook::jsi::JSError(runtime, "__exactUnixListen: path too long");
          }
          int backlog = 128;
          if (count > 1 && args[1].isNumber()) backlog = static_cast<int>(args[1].asNumber());
          std::string localCapability = "network:local:" + path;
          requireNetworkCapability(runtime, localCapability, "network:local");
          if (!checkCapability("fs:write:" + path)) {
            throw facebook::jsi::JSError(runtime, "Permission denied");
          }
          int fd = socket(AF_UNIX, SOCK_STREAM, 0);
          if (fd == -1) {
            throw facebook::jsi::JSError(runtime,
                ("socket(AF_UNIX) failed: " + std::string(strerror(errno))).c_str());
          }
          struct sockaddr_un addr;
          memset(&addr, 0, sizeof(addr));
          addr.sun_family = AF_UNIX;
          strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
          if (::bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) == -1) {
            int saved_errno = errno;
            ::close(fd);
            throw facebook::jsi::JSError(runtime,
                ("bind(AF_UNIX) failed for " + path + ": " + strerror(saved_errno)).c_str());
          }
          if (::listen(fd, backlog) == -1) {
            int saved_errno = errno;
            ::close(fd);
            ::unlink(path.c_str());
            throw facebook::jsi::JSError(runtime,
                ("listen(AF_UNIX) failed: " + std::string(strerror(saved_errno))).c_str());
          }
          int flags = fcntl(fd, F_GETFL, 0);
          if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
          int handle = registerSocketHandle(fd, localCapability);
          return facebook::jsi::Value(handle);
        });
    rt.global().setProperty(rt, "__exactUnixListen", std::move(unixListenFn));

    // __exactUnixAccept(handle) -> new handle or -1 (EAGAIN)
    // Identical to __exactTcpAccept but kept separate for clarity
    auto unixAcceptFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactUnixAccept"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactUnixAccept: handle required");
          }
          int handle = static_cast<int>(args[0].asNumber());
          SocketEntry listenEntry = requireSocketHandle(runtime, handle, "__exactUnixAccept");
          int listenFd = listenEntry.fd;
          struct sockaddr_un clientAddr;
          socklen_t clientLen = sizeof(clientAddr);
          int clientFd = ::accept(listenFd, reinterpret_cast<struct sockaddr*>(&clientAddr), &clientLen);
          if (clientFd == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return facebook::jsi::Value(-1);
            throw facebook::jsi::JSError(runtime,
                ("__exactUnixAccept error: " + std::string(strerror(errno))).c_str());
          }
          int flags = fcntl(clientFd, F_GETFL, 0);
          if (flags != -1) fcntl(clientFd, F_SETFL, flags | O_NONBLOCK);
          int newHandle =
              registerSocketHandle(clientFd, listenEntry.capability, listenEntry.owner);
          return facebook::jsi::Value(newHandle);
        });
    rt.global().setProperty(rt, "__exactUnixAccept", std::move(unixAcceptFn));

  // ============================================================
    // UDP (dgram) host functions
    // Reuses the native socket-handle registry for
    // the handle→fd mapping (same pattern as Unix sockets).
    // ============================================================

    // __exactUdpSocket(type) -> handle  (type: "udp4" or "udp6")
    auto udpSocketFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactUdpSocket"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          int family = AF_INET;
          if (count > 0 && args[0].isString()) {
            std::string type = args[0].toString(runtime).utf8(runtime);
            if (type == "udp6") family = AF_INET6;
          }
          int fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
          if (fd == -1) {
            throw facebook::jsi::JSError(runtime,
                ("socket(SOCK_DGRAM) failed: " + std::string(strerror(errno))).c_str());
          }
          int flags = fcntl(fd, F_GETFL, 0);
          if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
          // Enable SO_REUSEADDR so parent+child can both receive
          int reuse = 1;
          setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
          setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
          int handle = registerSocketHandle(fd, "");
          return facebook::jsi::Value(handle);
        });
    rt.global().setProperty(rt, "__exactUdpSocket", std::move(udpSocketFn));

    // __exactUdpBind(handle, host, port) -> JSON {address, port, family}
    auto udpBindFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactUdpBind"), 3,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactUdpBind: handle required");
          }
          int handle = static_cast<int>(args[0].asNumber());
          std::string host = "0.0.0.0";
          int port = 0;
          if (count > 1 && args[1].isString()) host = args[1].toString(runtime).utf8(runtime);
          if (count > 2 && args[2].isNumber()) port = static_cast<int>(args[2].asNumber());
          if (isIpv4MappedLiteral(host)) {
            throw facebook::jsi::JSError(
                runtime,
                "__exactUdpBind: IPv4-mapped IPv6 literals are not canonical; use IPv4");
          }
          std::string listenCapability =
              networkEndpointCapability("network:listen", host, port);
          requireNetworkCapability(runtime, listenCapability, "network:listen");
          int fd = requireSocketHandle(runtime, handle, "__exactUdpBind").fd;
          struct sockaddr_in addr4;
          struct sockaddr_in6 addr6;
          struct sockaddr* sa; socklen_t sa_len;
          if (host.find(':') != std::string::npos) {
            memset(&addr6, 0, sizeof(addr6));
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port = htons(port);
            if (inet_pton(AF_INET6, host.c_str(), &addr6.sin6_addr) != 1) {
              throw facebook::jsi::JSError(
                  runtime, ("__exactUdpBind: invalid IPv6 address " + host).c_str());
            }
            sa = reinterpret_cast<struct sockaddr*>(&addr6);
            sa_len = sizeof(addr6);
          } else {
            memset(&addr4, 0, sizeof(addr4));
            addr4.sin_family = AF_INET;
            addr4.sin_port = htons(port);
            if (inet_pton(AF_INET, host.c_str(), &addr4.sin_addr) != 1) {
              throw facebook::jsi::JSError(
                  runtime, ("__exactUdpBind: invalid IPv4 address " + host).c_str());
            }
            sa = reinterpret_cast<struct sockaddr*>(&addr4);
            sa_len = sizeof(addr4);
          }
          if (::bind(fd, sa, sa_len) == -1) {
            throw facebook::jsi::JSError(runtime,
                ("bind failed: " + std::string(strerror(errno))).c_str());
          }
          setSocketCapability(runtime, handle, listenCapability, "__exactUdpBind");
          // Get actual bound address
          struct sockaddr_storage bound; socklen_t boundLen = sizeof(bound);
          getsockname(fd, reinterpret_cast<struct sockaddr*>(&bound), &boundLen);
          auto json = socketAddressJson(reinterpret_cast<const struct sockaddr*>(&bound));
          if (!json) return facebook::jsi::Value::null();
          return facebook::jsi::String::createFromUtf8(runtime, *json);
        });
    rt.global().setProperty(rt, "__exactUdpBind", std::move(udpBindFn));

    // __exactUdpSend(handle, data, port, host) -> bytes sent
    auto udpSendFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactUdpSend"), 4,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 4 || !args[0].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactUdpSend: handle, data, port, host required");
          }
          int handle = static_cast<int>(args[0].asNumber());
          int port = static_cast<int>(args[2].asNumber());
          std::string host = args[3].toString(runtime).utf8(runtime);
          if (port <= 0 || port > 65535) {
            throw facebook::jsi::JSError(runtime, "__exactUdpSend: port out of range");
          }
          if (isIpv4MappedLiteral(host)) {
            throw facebook::jsi::JSError(
                runtime,
                "__exactUdpSend: IPv4-mapped IPv6 literals are not canonical; use IPv4");
          }
          // Get data bytes
          const uint8_t* dataPtr = nullptr; size_t dataLen = 0;
          std::string strData;
          if (args[1].isString()) {
            strData = args[1].toString(runtime).utf8(runtime);
            dataPtr = reinterpret_cast<const uint8_t*>(strData.data());
            dataLen = strData.size();
          } else if (args[1].isObject()) {
            auto obj = args[1].asObject(runtime);
            if (extractArrayBufferView(runtime, obj, dataPtr, dataLen)) {
              // dataPtr/dataLen filled by the shared bounds-checked extractor.
            }
          }
          if (!dataPtr || dataLen == 0) {
            throw facebook::jsi::JSError(runtime, "__exactUdpSend: invalid data");
          }
          // Build destination address
          struct sockaddr_in addr4;
          struct sockaddr_in6 addr6;
          struct sockaddr* sa; socklen_t sa_len;
          if (host.find(':') != std::string::npos) {
            memset(&addr6, 0, sizeof(addr6));
            addr6.sin6_family = AF_INET6;
            addr6.sin6_port = htons(port);
            if (inet_pton(AF_INET6, host.c_str(), &addr6.sin6_addr) != 1) {
              throw facebook::jsi::JSError(
                  runtime, ("__exactUdpSend: invalid IPv6 address " + host).c_str());
            }
            sa = reinterpret_cast<struct sockaddr*>(&addr6);
            sa_len = sizeof(addr6);
          } else {
            memset(&addr4, 0, sizeof(addr4));
            addr4.sin_family = AF_INET;
            addr4.sin_port = htons(port);
            if (inet_pton(AF_INET, host.c_str(), &addr4.sin_addr) != 1) {
              throw facebook::jsi::JSError(
                  runtime, ("__exactUdpSend: invalid IPv4 address " + host).c_str());
            }
            sa = reinterpret_cast<struct sockaddr*>(&addr4);
            sa_len = sizeof(addr4);
          }
          ssize_t sent = -1;
          int sendError = 0;
          if (ex_host_is_armed() == 1) {
            // @ref LLP 0021#wp6--convert-network-effects-and-protected-peers —
            // The first send (and every lease renewal) authorizes requested,
            // candidate, and committed literal destination facts immediately
            // before sendto. Stable repeats use the exact endpoint lease.
            auto socketIo = requireTypedUdpSendIo(
                runtime, handle, host, static_cast<uint16_t>(port));
            sent = ::sendto(socketIo.fd, dataPtr, dataLen, 0, sa, sa_len);
            if (sent == -1) sendError = errno;
          } else {
            SocketEntry socket =
                requireSocketHandle(runtime, handle, "__exactUdpSend");
            requireNetworkCapability(
                runtime,
                networkEndpointCapability("network:connect", host, port),
                "network:connect");
            sent = ::sendto(socket.fd, dataPtr, dataLen, 0, sa, sa_len);
            if (sent == -1) sendError = errno;
          }
          if (sent == -1) {
            if (sendError == EAGAIN || sendError == EWOULDBLOCK) {
              return facebook::jsi::Value(0);
            }
            throw facebook::jsi::JSError(runtime,
                ("sendto failed: " + std::string(strerror(sendError))).c_str());
          }
          return facebook::jsi::Value(static_cast<int>(sent));
        });
    rt.global().setProperty(rt, "__exactUdpSend", std::move(udpSendFn));

    // __exactUdpRecv(handle) -> JSON {data (base64), address, port, family} or null (EAGAIN)
    auto udpRecvFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactUdpRecv"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) {
            throw facebook::jsi::JSError(runtime, "__exactUdpRecv: handle required");
          }
          int handle = static_cast<int>(args[0].asNumber());
          // @ref LLP 0013#policy — (ENG-22819) — receiving datagrams is listening authority; a
          // connect-only/unbound handle (empty capability) must not receive for
          // a third-party principal.
          int fd =
              requireSocketHandle(runtime, handle, "__exactUdpRecv", /*requireCapability=*/true)
                  .fd;
          uint8_t buf[65536];
          struct sockaddr_storage from; socklen_t fromLen = sizeof(from);
          ssize_t n = ::recvfrom(fd, buf, sizeof(buf), 0,
              reinterpret_cast<struct sockaddr*>(&from), &fromLen);
          if (n == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return facebook::jsi::Value::null();
            throw facebook::jsi::JSError(runtime,
                ("recvfrom failed: " + std::string(strerror(errno))).c_str());
          }
          if (n == 0) return facebook::jsi::Value::null();
          // Return data as Uint8Array + sender info as JSON. Dual-stack IPv6
          // sockets report IPv4 senders as ::ffff:a.b.c.d; keep every JS and
          // CapSec-facing representation on the canonical embedded IPv4 form.
          auto fromText =
              addressText(reinterpret_cast<const struct sockaddr*>(&from));
          if (!fromText) return facebook::jsi::Value::null();
          int fromPort = 0;
          if (from.ss_family == AF_INET) {
            auto* s = reinterpret_cast<struct sockaddr_in*>(&from);
            fromPort = ntohs(s->sin_port);
          } else if (from.ss_family == AF_INET6) {
            auto* s = reinterpret_cast<struct sockaddr_in6*>(&from);
            fromPort = ntohs(s->sin6_port);
          } else { return facebook::jsi::Value::null(); }
          const char* family =
              from.ss_family == AF_INET ||
                  isIpv4MappedAddress(reinterpret_cast<const struct sockaddr*>(&from))
              ? "IPv4"
              : "IPv6";
          // Return as object with Uint8Array data and rinfo
          auto result = facebook::jsi::Object(runtime);
          // Create Uint8Array from data using makeUint8Array helper
          std::vector<uint8_t> dataVec(buf, buf + n);
          auto typedArray = makeUint8Array(runtime, std::move(dataVec));
          result.setProperty(runtime, "data", std::move(typedArray));
          result.setProperty(runtime, "address", facebook::jsi::String::createFromUtf8(runtime, *fromText));
          result.setProperty(runtime, "port", facebook::jsi::Value(fromPort));
          result.setProperty(runtime, "family", facebook::jsi::String::createFromUtf8(runtime, family));
          result.setProperty(runtime, "size", facebook::jsi::Value(static_cast<int>(n)));
          return result;
        });
    rt.global().setProperty(rt, "__exactUdpRecv", std::move(udpRecvFn));

    // __exactUdpClose(handle) -> 0
    auto udpCloseFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactUdpClose"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) throw facebook::jsi::JSError(runtime, "__exactUdpClose: handle required");
          int handle = static_cast<int>(args[0].asNumber());
          int fd = takeSocketFd(runtime, handle, "__exactUdpClose");
          if (fd >= 0) ::close(fd);
          return facebook::jsi::Value(0);
        });
    rt.global().setProperty(rt, "__exactUdpClose", std::move(udpCloseFn));

    // __exactUdpAddress(handle) -> JSON {address, port, family}
    auto udpAddressFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactUdpAddress"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) return facebook::jsi::Value::null();
          int handle = static_cast<int>(args[0].asNumber());
          SocketEntry entry;
          // @ref LLP 0013#policy — (ENG-22819) — the bound address (incl. an implicitly-assigned
          // ephemeral port) is not exposed for a capability-less handle.
          if (!trySocketHandle(runtime, handle, "__exactUdpAddress", entry,
                               /*requireCapability=*/true)) {
            return facebook::jsi::Value::null();
          }
          int fd = entry.fd;
          struct sockaddr_storage addr; socklen_t addrLen = sizeof(addr);
          if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &addrLen) == -1)
            return facebook::jsi::Value::null();
          auto json = socketAddressJson(reinterpret_cast<const struct sockaddr*>(&addr));
          if (!json) return facebook::jsi::Value::null();
          return facebook::jsi::String::createFromUtf8(runtime, *json);
        });
    rt.global().setProperty(rt, "__exactUdpAddress", std::move(udpAddressFn));

    // __exactUdpFromFd(fd) -> handle
    auto udpFromFdFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactUdpFromFd"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) throw facebook::jsi::JSError(runtime, "__exactUdpFromFd: fd required");
          int fd = static_cast<int>(args[0].asNumber());
          if (fd < 0) throw facebook::jsi::JSError(runtime, "__exactUdpFromFd: invalid fd");
          requireRawSocketAdoptionAllowed(runtime, fd, "__exactUdpFromFd");
          int flags = fcntl(fd, F_GETFL, 0);
          if (flags != -1) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
          int handle = registerSocketHandle(fd, "");
          return facebook::jsi::Value(handle);
        });
    rt.global().setProperty(rt, "__exactUdpFromFd", std::move(udpFromFdFn));

    // __exactUdpGetFd(handle) -> fd
    auto udpGetFdFn = facebook::jsi::Function::createFromHostFunction(
        rt, facebook::jsi::PropNameID::forAscii(rt, "__exactUdpGetFd"), 1,
        [](facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
           const facebook::jsi::Value* args, size_t count) -> facebook::jsi::Value {
          if (count < 1 || !args[0].isNumber()) return facebook::jsi::Value(-1);
          int handle = static_cast<int>(args[0].asNumber());
          SocketEntry entry;
          // @ref LLP 0013#policy — (ENG-22819) — the raw fd is authority (it can be exported over
          // IPC / operated on directly), so it is withheld for a capability-less
          // handle held by a third-party principal.
          if (!trySocketHandle(runtime, handle, "__exactUdpGetFd", entry,
                               /*requireCapability=*/true)) {
            return facebook::jsi::Value(-1);
          }
          exactRegisterTransferableFd(entry.fd, entry.owner);
          return facebook::jsi::Value(entry.fd);
        });
    rt.global().setProperty(rt, "__exactUdpGetFd", std::move(udpGetFdFn));

  } // end TCP + Unix socket host functions

  // Native TLS bridge (ENG-23492): the __exactTlsEngine* host functions ride
  // the TCP sockets above, so they install (and lazy-load) together through
  // __exactEnsureNet — tls.js can rely on their presence whenever TCP works.
  installTlsHostFunctions(handle);
}
