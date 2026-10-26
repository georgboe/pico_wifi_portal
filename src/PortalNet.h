/**
 * @file PortalNet.h
 * @brief Minimal lwIP raw-API DNS, DHCP and HTTP servers for the captive
 *        portal SoftAP.
 *
 * Every method here must be called with the lwIP lock held
 * (cyw43_arch_lwip_begin/end). lwIP callbacks may run from the CYW43 async
 * context, so they only touch fixed buffers and never allocate from the heap.
 *
 * @copyright Copyright (c) 2026 Tran Nguyen Hien. All rights reserved.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"

namespace pico_wifi_portal_detail {

// Answers every A query with the portal address so any hostname reaches the
// portal. Other query types get an empty NOERROR answer.
class DnsServer {
public:
  DnsServer() = default;
  ~DnsServer() { stop(); }
  DnsServer(const DnsServer&) = delete;
  DnsServer& operator=(const DnsServer&) = delete;

  bool start(struct netif* boundNetif, uint16_t port, uint32_t answerAddress);
  void stop();

private:
  static void onReceive(void* arg, struct udp_pcb* pcb, struct pbuf* p,
                        const ip_addr_t* address, u16_t port);
  void handle(struct pbuf* p, const ip_addr_t* address, u16_t port);

  static constexpr size_t kMaxMessageSize = 512;
  static constexpr size_t kAnswerSize = 16;

  struct udp_pcb* _pcb = nullptr;
  struct netif* _netif = nullptr;
  uint32_t _answerAddress = 0;
  uint8_t _buffer[kMaxMessageSize + kAnswerSize] = {};
};

// SoftAP DHCP server with a fixed pool of consecutive addresses.
class DhcpServer {
public:
  static constexpr size_t kLeaseCount = 11;

  DhcpServer() = default;
  ~DhcpServer() { stop(); }
  DhcpServer(const DhcpServer&) = delete;
  DhcpServer& operator=(const DhcpServer&) = delete;

  bool start(struct netif* boundNetif,
             uint32_t serverAddress,
             uint32_t gateway,
             uint32_t subnetMask,
             uint32_t firstLeaseAddress);
  void stop();

private:
  struct Lease {
    uint8_t mac[6];
    uint32_t expiresAtMs;
    bool used;
  };

  static void onReceive(void* arg, struct udp_pcb* pcb, struct pbuf* p,
                        const ip_addr_t* address, u16_t port);
  void handle(struct pbuf* p);
  int findLease(const uint8_t* mac) const;
  int allocateLease(const uint8_t* mac, uint32_t now);
  void reply(uint8_t messageType, int leaseIndex);

  static constexpr size_t kMaxMessageSize = 548;
  static constexpr uint32_t kLeaseSeconds = 7200;
  static constexpr uint32_t kOfferHoldMs = 30000;

  struct udp_pcb* _pcb = nullptr;
  struct netif* _netif = nullptr;
  uint32_t _serverAddress = 0;
  uint32_t _gateway = 0;
  uint32_t _subnetMask = 0;
  uint32_t _firstLeaseAddress = 0;
  Lease _leases[kLeaseCount] = {};
  uint8_t _buffer[kMaxMessageSize] = {};
};

class HttpServer;

enum class HttpMethod : uint8_t { Get, Post, Other };

class HttpRequest {
public:
  HttpMethod method() const { return _method; }
  std::string_view path() const { return _path; }
  // First matching URL-encoded argument from the query string, then the
  // request body. Returns an empty string when absent.
  std::string arg(std::string_view name) const;

  void sendHeader(std::string_view name, std::string_view value);
  void send(int status, const char* contentType, std::string_view body);
  // The body must stay valid until the response is sent (flash constants).
  void sendStatic(int status, const char* contentType, const char* body);
  bool sent() const { return _sent; }

private:
  friend class HttpServer;
  HttpRequest(HttpServer& server, size_t connectionIndex)
      : _server(server), _connectionIndex(connectionIndex) {}

  std::string buildHead(int status, const char* contentType,
                        size_t contentLength) const;

  HttpServer& _server;
  size_t _connectionIndex;
  HttpMethod _method = HttpMethod::Other;
  std::string_view _path;
  std::string_view _query;
  std::string_view _body;
  std::string _headers;
  bool _sent = false;
};

class HttpServer {
public:
  using RequestHandler = void (*)(void* context, HttpRequest& request);

  HttpServer() = default;
  ~HttpServer() { stop(); }
  HttpServer(const HttpServer&) = delete;
  HttpServer& operator=(const HttpServer&) = delete;

  bool start(struct netif* boundNetif, uint16_t port);
  void stop();
  // Dispatches complete requests to the handler from the caller's thread.
  void poll(RequestHandler handler, void* context);

private:
  friend class HttpRequest;

  static constexpr size_t kMaxConnections = 4;
  static constexpr size_t kRxCapacity = 2048;
  static constexpr uint32_t kReceiveTimeoutMs = 10000;
  static constexpr uint32_t kSendTimeoutMs = 30000;
  static constexpr uint8_t kPollInterval = 2;  // Units of 500 ms.

  enum class Phase : uint8_t { Free, Receiving, Ready, Sending };

  struct Connection {
    HttpServer* server;
    struct tcp_pcb* pcb;
    Phase phase;
    bool overflow;
    size_t rxLength;
    size_t headerLength;
    size_t contentLength;
    uint32_t activityAt;
    std::string head;
    size_t headSent;
    const char* body;
    size_t bodyLength;
    size_t bodySent;
    char rx[kRxCapacity + 1];
  };

  static err_t onAccept(void* arg, struct tcp_pcb* pcb, err_t err);
  static err_t onReceive(void* arg, struct tcp_pcb* pcb, struct pbuf* p,
                         err_t err);
  static err_t onSent(void* arg, struct tcp_pcb* pcb, u16_t length);
  static err_t onPoll(void* arg, struct tcp_pcb* pcb);
  static void onError(void* arg, err_t err);

  static void updateRequestState(Connection& connection);
  static bool parseRequest(Connection& connection, HttpRequest& request);
  // Both return false when the pcb was aborted (callbacks must then return
  // ERR_ABRT).
  static bool release(Connection& connection, bool abort);
  static bool pump(Connection& connection);
  void beginResponse(size_t connectionIndex, std::string head,
                     const char* body, size_t bodyLength);

  struct tcp_pcb* _listener = nullptr;
  Connection _connections[kMaxConnections] = {};
};

// Allocated only while the portal is active.
struct PortalServices {
  DnsServer dns;
  DhcpServer dhcp;
  HttpServer http;
};

}  // namespace pico_wifi_portal_detail
