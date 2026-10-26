/**
 * @file PortalNet.cpp
 * @brief Minimal lwIP raw-API DNS, DHCP and HTTP servers for the captive
 *        portal SoftAP.
 *
 * @copyright Copyright (c) 2026 Tran Nguyen Hien. All rights reserved.
 */

#include "PortalNet.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "lwip/def.h"
#include "pico/time.h"

namespace pico_wifi_portal_detail {

namespace {
uint32_t nowMs() { return to_ms_since_boot(get_absolute_time()); }

uint16_t readBE16(const uint8_t* data) {
  return static_cast<uint16_t>((data[0] << 8) | data[1]);
}

void writeBE16(uint8_t* data, uint16_t value) {
  data[0] = static_cast<uint8_t>(value >> 8);
  data[1] = static_cast<uint8_t>(value);
}

uint32_t readBE32(const uint8_t* data) {
  return (static_cast<uint32_t>(data[0]) << 24) |
         (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) |
         static_cast<uint32_t>(data[3]);
}

void writeBE32(uint8_t* data, uint32_t value) {
  data[0] = static_cast<uint8_t>(value >> 24);
  data[1] = static_cast<uint8_t>(value >> 16);
  data[2] = static_cast<uint8_t>(value >> 8);
  data[3] = static_cast<uint8_t>(value);
}

bool sendUdp(struct udp_pcb* pcb, struct netif* netif, const uint8_t* data,
             size_t length, const ip_addr_t* address, u16_t port) {
  struct pbuf* p =
      pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(length), PBUF_RAM);
  if (!p) return false;
  const bool sent = pbuf_take(p, data, static_cast<u16_t>(length)) == ERR_OK &&
                    udp_sendto_if(pcb, p, address, port, netif) == ERR_OK;
  pbuf_free(p);
  return sent;
}
}  // namespace

// ---------------------------------------------------------------------------
// DNS

bool DnsServer::start(struct netif* boundNetif, uint16_t port,
                      uint32_t answerAddress) {
  stop();
  _pcb = udp_new_ip_type(IPADDR_TYPE_V4);
  if (!_pcb) return false;
  _netif = boundNetif;
  _answerAddress = answerAddress;
  udp_bind_netif(_pcb, boundNetif);
  if (udp_bind(_pcb, IP_ANY_TYPE, port) != ERR_OK) {
    stop();
    return false;
  }
  udp_recv(_pcb, &DnsServer::onReceive, this);
  return true;
}

void DnsServer::stop() {
  if (!_pcb) return;
  udp_recv(_pcb, nullptr, nullptr);
  udp_remove(_pcb);
  _pcb = nullptr;
  _netif = nullptr;
}

void DnsServer::onReceive(void* arg, struct udp_pcb*, struct pbuf* p,
                          const ip_addr_t* address, u16_t port) {
  static_cast<DnsServer*>(arg)->handle(p, address, port);
  pbuf_free(p);
}

void DnsServer::handle(struct pbuf* p, const ip_addr_t* address, u16_t port) {
  if (p->tot_len > kMaxMessageSize) return;
  const size_t length = pbuf_copy_partial(p, _buffer, kMaxMessageSize, 0);
  if (length < 12) return;

  // Queries only (QR = 0), standard opcode, exactly one question.
  if ((_buffer[2] & 0x80) != 0 || ((_buffer[2] >> 3) & 0x0F) != 0 ||
      readBE16(_buffer + 4) != 1) {
    return;
  }

  size_t position = 12;
  while (true) {
    if (position >= length) return;
    const uint8_t labelLength = _buffer[position];
    if (labelLength == 0) {
      ++position;
      break;
    }
    if ((labelLength & 0xC0) != 0) return;  // No compression in questions.
    position += 1 + labelLength;
  }
  if (position + 4 > length) return;

  const uint16_t queryType = readBE16(_buffer + position);
  const uint16_t queryClass = readBE16(_buffer + position + 2) & 0x7FFF;
  position += 4;
  const bool answer = (queryType == 1 || queryType == 255) && queryClass == 1;

  // Response header: QR + AA, keep RD, NOERROR. Drop any extra records.
  _buffer[2] = static_cast<uint8_t>(0x84 | (_buffer[2] & 0x01));
  _buffer[3] = 0x00;
  writeBE16(_buffer + 6, answer ? 1 : 0);
  writeBE16(_buffer + 8, 0);
  writeBE16(_buffer + 10, 0);

  if (answer) {
    uint8_t* record = _buffer + position;
    writeBE16(record, 0xC00C);  // Pointer to the question name.
    writeBE16(record + 2, 1);   // A
    writeBE16(record + 4, 1);   // IN
    writeBE32(record + 6, 60);  // TTL
    writeBE16(record + 10, 4);
    writeBE32(record + 12, _answerAddress);
    position += kAnswerSize;
  }

  sendUdp(_pcb, _netif, _buffer, position, address, port);
}

// ---------------------------------------------------------------------------
// DHCP

namespace {
constexpr uint8_t kBootRequest = 1;
constexpr uint8_t kBootReply = 2;
constexpr size_t kBootpFixedSize = 236;
constexpr size_t kOptionsOffset = kBootpFixedSize + 4;
constexpr size_t kMinimumReplySize = 300;
constexpr uint32_t kMagicCookie = 0x63825363UL;
constexpr u16_t kDhcpClientPort = 68;
constexpr u16_t kDhcpServerPort = 67;

constexpr uint8_t kDhcpDiscover = 1;
constexpr uint8_t kDhcpOffer = 2;
constexpr uint8_t kDhcpRequest = 3;
constexpr uint8_t kDhcpDecline = 4;
constexpr uint8_t kDhcpAck = 5;
constexpr uint8_t kDhcpNak = 6;
constexpr uint8_t kDhcpRelease = 7;

constexpr uint8_t kOptionPad = 0;
constexpr uint8_t kOptionSubnetMask = 1;
constexpr uint8_t kOptionRouter = 3;
constexpr uint8_t kOptionDNS = 6;
constexpr uint8_t kOptionRequestedIP = 50;
constexpr uint8_t kOptionLeaseTime = 51;
constexpr uint8_t kOptionMessageType = 53;
constexpr uint8_t kOptionServerID = 54;
constexpr uint8_t kOptionEnd = 255;

uint8_t* putOption32(uint8_t* out, uint8_t option, uint32_t value) {
  out[0] = option;
  out[1] = 4;
  writeBE32(out + 2, value);
  return out + 6;
}
}  // namespace

bool DhcpServer::start(struct netif* boundNetif,
                       uint32_t serverAddress,
                       uint32_t gateway,
                       uint32_t subnetMask,
                       uint32_t firstLeaseAddress) {
  stop();
  _pcb = udp_new_ip_type(IPADDR_TYPE_V4);
  if (!_pcb) return false;
  ip_set_option(_pcb, SOF_BROADCAST);
  // Never answer DHCP on the upstream STA network.
  udp_bind_netif(_pcb, boundNetif);
  if (udp_bind(_pcb, IP_ANY_TYPE, kDhcpServerPort) != ERR_OK) {
    stop();
    return false;
  }
  _netif = boundNetif;
  _serverAddress = serverAddress;
  _gateway = gateway;
  _subnetMask = subnetMask;
  _firstLeaseAddress = firstLeaseAddress;
  memset(_leases, 0, sizeof(_leases));
  udp_recv(_pcb, &DhcpServer::onReceive, this);
  return true;
}

void DhcpServer::stop() {
  if (!_pcb) return;
  udp_recv(_pcb, nullptr, nullptr);
  udp_remove(_pcb);
  _pcb = nullptr;
  _netif = nullptr;
}

void DhcpServer::onReceive(void* arg, struct udp_pcb*, struct pbuf* p,
                           const ip_addr_t*, u16_t) {
  static_cast<DhcpServer*>(arg)->handle(p);
  pbuf_free(p);
}

int DhcpServer::findLease(const uint8_t* mac) const {
  for (size_t i = 0; i < kLeaseCount; ++i) {
    if (_leases[i].used && memcmp(_leases[i].mac, mac, 6) == 0) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

int DhcpServer::allocateLease(const uint8_t* mac, uint32_t now) {
  const int existing = findLease(mac);
  if (existing >= 0) return existing;
  for (size_t i = 0; i < kLeaseCount; ++i) {
    Lease& lease = _leases[i];
    if (!lease.used || static_cast<int32_t>(now - lease.expiresAtMs) >= 0) {
      memcpy(lease.mac, mac, 6);
      lease.used = true;
      lease.expiresAtMs = now + kOfferHoldMs;
      return static_cast<int>(i);
    }
  }
  return -1;
}

void DhcpServer::handle(struct pbuf* p) {
  const size_t length = pbuf_copy_partial(p, _buffer, sizeof(_buffer), 0);
  if (length < kOptionsOffset || _buffer[0] != kBootRequest ||
      _buffer[1] != 1 || _buffer[2] != 6 ||
      readBE32(_buffer + kBootpFixedSize) != kMagicCookie) {
    return;
  }

  uint8_t messageType = 0;
  uint32_t requestedAddress = 0;
  uint32_t serverID = 0;
  for (size_t i = kOptionsOffset; i < length;) {
    const uint8_t option = _buffer[i];
    if (option == kOptionEnd) break;
    if (option == kOptionPad) {
      ++i;
      continue;
    }
    if (i + 2 > length) break;
    const uint8_t optionLength = _buffer[i + 1];
    const uint8_t* value = _buffer + i + 2;
    if (i + 2 + optionLength > length) break;
    if (option == kOptionMessageType && optionLength == 1) {
      messageType = value[0];
    } else if (option == kOptionRequestedIP && optionLength == 4) {
      requestedAddress = readBE32(value);
    } else if (option == kOptionServerID && optionLength == 4) {
      serverID = readBE32(value);
    }
    i += 2 + optionLength;
  }

  uint8_t mac[6];
  memcpy(mac, _buffer + 28, sizeof(mac));
  const uint32_t now = nowMs();

  switch (messageType) {
    case kDhcpDiscover: {
      const int index = allocateLease(mac, now);
      if (index >= 0) reply(kDhcpOffer, index);
      break;
    }
    case kDhcpRequest: {
      // The client selected another server's offer.
      if (serverID != 0 && serverID != _serverAddress) {
        const int index = findLease(mac);
        if (index >= 0 && static_cast<int32_t>(
                              _leases[index].expiresAtMs - now) <=
                              static_cast<int32_t>(kOfferHoldMs)) {
          _leases[index].used = false;
        }
        break;
      }
      if (requestedAddress == 0) requestedAddress = readBE32(_buffer + 12);
      const uint32_t offset = requestedAddress - _firstLeaseAddress;
      if (offset >= kLeaseCount) {
        reply(kDhcpNak, -1);
        break;
      }
      Lease& lease = _leases[offset];
      const bool ownedByOther =
          lease.used && memcmp(lease.mac, mac, 6) != 0 &&
          static_cast<int32_t>(now - lease.expiresAtMs) < 0;
      if (ownedByOther) {
        reply(kDhcpNak, -1);
        break;
      }
      // A client moving to a different address releases its previous one.
      const int previous = findLease(mac);
      if (previous >= 0 && previous != static_cast<int>(offset)) {
        _leases[previous].used = false;
      }
      memcpy(lease.mac, mac, 6);
      lease.used = true;
      lease.expiresAtMs = now + kLeaseSeconds * 1000UL;
      reply(kDhcpAck, static_cast<int>(offset));
      break;
    }
    case kDhcpDecline: {
      // Another host already uses the address; keep it out of the pool.
      const int index = findLease(mac);
      if (index >= 0) {
        memset(_leases[index].mac, 0xFF, 6);
        _leases[index].expiresAtMs = now + kLeaseSeconds * 1000UL;
      }
      break;
    }
    case kDhcpRelease: {
      const int index = findLease(mac);
      if (index >= 0) _leases[index].used = false;
      break;
    }
    default:
      break;
  }
}

void DhcpServer::reply(uint8_t messageType, int leaseIndex) {
  // Reuse the request in place: xid, flags, giaddr and chaddr are preserved.
  _buffer[0] = kBootReply;
  _buffer[3] = 0;                     // hops
  memset(_buffer + 8, 0, 2);          // secs
  memset(_buffer + 12, 0, 4);         // ciaddr
  writeBE32(_buffer + 16, leaseIndex >= 0
                              ? _firstLeaseAddress + static_cast<uint32_t>(leaseIndex)
                              : 0);   // yiaddr
  writeBE32(_buffer + 20, _serverAddress);  // siaddr
  memset(_buffer + 44, 0, 192);       // sname + file
  writeBE32(_buffer + kBootpFixedSize, kMagicCookie);

  uint8_t* out = _buffer + kOptionsOffset;
  *out++ = kOptionMessageType;
  *out++ = 1;
  *out++ = messageType;
  out = putOption32(out, kOptionServerID, _serverAddress);
  if (messageType != kDhcpNak) {
    out = putOption32(out, kOptionLeaseTime, kLeaseSeconds);
    out = putOption32(out, kOptionSubnetMask, _subnetMask);
    out = putOption32(out, kOptionRouter, _gateway);
    out = putOption32(out, kOptionDNS, _serverAddress);
  }
  *out++ = kOptionEnd;

  const size_t used = static_cast<size_t>(out - _buffer);
  const size_t length = std::max(used, kMinimumReplySize);
  if (length > used) memset(out, 0, length - used);

  // Clients without an address cannot receive unicast before ARP, so reply
  // with a limited broadcast on the SoftAP interface.
  sendUdp(_pcb, _netif, _buffer, length, IP_ADDR_BROADCAST, kDhcpClientPort);
}

// ---------------------------------------------------------------------------
// HTTP

namespace {
const char* statusText(int status) {
  switch (status) {
    case 200: return "OK";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 302: return "Found";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 409: return "Conflict";
    case 413: return "Payload Too Large";
    case 500: return "Internal Server Error";
    case 503: return "Service Unavailable";
    default: return "";
  }
}

int hexValue(char character) {
  if (character >= '0' && character <= '9') return character - '0';
  if (character >= 'a' && character <= 'f') return character - 'a' + 10;
  if (character >= 'A' && character <= 'F') return character - 'A' + 10;
  return -1;
}

std::string urlDecode(std::string_view value) {
  std::string decoded;
  decoded.reserve(value.size());
  for (size_t i = 0; i < value.size(); ++i) {
    const char character = value[i];
    if (character == '+') {
      decoded += ' ';
    } else if (character == '%' && i + 2 < value.size() &&
               hexValue(value[i + 1]) >= 0 && hexValue(value[i + 2]) >= 0) {
      decoded += static_cast<char>((hexValue(value[i + 1]) << 4) |
                                   hexValue(value[i + 2]));
      i += 2;
    } else {
      decoded += character;
    }
  }
  return decoded;
}

bool findArg(std::string_view source, std::string_view name,
             std::string& value) {
  while (!source.empty()) {
    const size_t separator = source.find('&');
    const std::string_view pair = source.substr(0, separator);
    const size_t equals = pair.find('=');
    if (urlDecode(pair.substr(0, equals)) == name) {
      value = equals == std::string_view::npos
                  ? std::string()
                  : urlDecode(pair.substr(equals + 1));
      return true;
    }
    if (separator == std::string_view::npos) break;
    source.remove_prefix(separator + 1);
  }
  return false;
}

bool startsWithIgnoreCase(const char* text, size_t length, const char* prefix) {
  const size_t prefixLength = strlen(prefix);
  if (length < prefixLength) return false;
  for (size_t i = 0; i < prefixLength; ++i) {
    char character = text[i];
    if (character >= 'A' && character <= 'Z') character += 'a' - 'A';
    if (character != prefix[i]) return false;
  }
  return true;
}
}  // namespace

std::string HttpRequest::arg(std::string_view name) const {
  std::string value;
  if (findArg(_query, name, value)) return value;
  findArg(_body, name, value);
  return value;
}

void HttpRequest::sendHeader(std::string_view name, std::string_view value) {
  _headers.append(name.data(), name.size());
  _headers += ": ";
  _headers.append(value.data(), value.size());
  _headers += "\r\n";
}

std::string HttpRequest::buildHead(int status, const char* contentType,
                                   size_t contentLength) const {
  char statusLine[96];
  snprintf(statusLine, sizeof(statusLine),
           "HTTP/1.1 %d %s\r\nContent-Length: %u\r\n", status,
           statusText(status), static_cast<unsigned>(contentLength));
  std::string head;
  head.reserve(160 + _headers.size());
  head = statusLine;
  if (contentType && contentType[0] != '\0') {
    head += "Content-Type: ";
    head += contentType;
    head += "\r\n";
  }
  head += _headers;
  head += "Connection: close\r\n\r\n";
  return head;
}

void HttpRequest::send(int status, const char* contentType,
                       std::string_view body) {
  if (_sent) return;
  _sent = true;
  std::string head = buildHead(status, contentType, body.size());
  head.append(body.data(), body.size());
  _server.beginResponse(_connectionIndex, std::move(head), nullptr, 0);
}

void HttpRequest::sendStatic(int status, const char* contentType,
                             const char* body) {
  if (_sent) return;
  _sent = true;
  const size_t length = strlen(body);
  _server.beginResponse(_connectionIndex,
                        buildHead(status, contentType, length), body, length);
}

bool HttpServer::start(struct netif* boundNetif, uint16_t port) {
  stop();
  struct tcp_pcb* pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
  if (!pcb) return false;
  // Serve the portal on the SoftAP only, never on the upstream network.
  tcp_bind_netif(pcb, boundNetif);
  if (tcp_bind(pcb, IP_ANY_TYPE, port) != ERR_OK) {
    tcp_abort(pcb);
    return false;
  }
  _listener = tcp_listen_with_backlog(pcb, kMaxConnections);
  if (!_listener) {
    tcp_abort(pcb);
    return false;
  }
  for (Connection& connection : _connections) {
    connection.server = this;
    connection.pcb = nullptr;
    connection.phase = Phase::Free;
  }
  tcp_arg(_listener, this);
  tcp_accept(_listener, &HttpServer::onAccept);
  return true;
}

void HttpServer::stop() {
  for (Connection& connection : _connections) {
    release(connection, true);
  }
  if (_listener) {
    tcp_arg(_listener, nullptr);
    tcp_accept(_listener, nullptr);
    if (tcp_close(_listener) != ERR_OK) tcp_abort(_listener);
    _listener = nullptr;
  }
}

err_t HttpServer::onAccept(void* arg, struct tcp_pcb* pcb, err_t err) {
  HttpServer* server = static_cast<HttpServer*>(arg);
  if (err != ERR_OK || !pcb || !server) return ERR_VAL;

  for (Connection& connection : server->_connections) {
    if (connection.phase != Phase::Free) continue;
    connection.pcb = pcb;
    connection.phase = Phase::Receiving;
    connection.overflow = false;
    connection.rxLength = 0;
    connection.headerLength = 0;
    connection.contentLength = 0;
    connection.activityAt = nowMs();
    connection.head.clear();  // Keeps capacity: no heap use in this context.
    connection.headSent = 0;
    connection.body = nullptr;
    connection.bodyLength = 0;
    connection.bodySent = 0;
    tcp_arg(pcb, &connection);
    tcp_recv(pcb, &HttpServer::onReceive);
    tcp_sent(pcb, &HttpServer::onSent);
    tcp_err(pcb, &HttpServer::onError);
    tcp_poll(pcb, &HttpServer::onPoll, kPollInterval);
    return ERR_OK;
  }

  // Every slot is busy; captive probes will simply retry.
  tcp_abort(pcb);
  return ERR_ABRT;
}

err_t HttpServer::onReceive(void* arg, struct tcp_pcb* pcb, struct pbuf* p,
                            err_t err) {
  Connection* connection = static_cast<Connection*>(arg);
  if (!connection) {
    if (p) pbuf_free(p);
    tcp_abort(pcb);
    return ERR_ABRT;
  }
  if (!p) {
    // Remote closed. A pending response is still delivered after half-close.
    if (connection->phase == Phase::Sending) return ERR_OK;
    return release(*connection, false) ? ERR_OK : ERR_ABRT;
  }
  if (err != ERR_OK) {
    pbuf_free(p);
    return err;
  }

  if (connection->phase == Phase::Receiving) {
    const size_t space = kRxCapacity - connection->rxLength;
    const size_t copied = pbuf_copy_partial(
        p, connection->rx + connection->rxLength,
        static_cast<u16_t>(std::min<size_t>(p->tot_len, space)), 0);
    connection->rxLength += copied;
    connection->rx[connection->rxLength] = '\0';
    if (p->tot_len > space) connection->overflow = true;
    connection->activityAt = nowMs();
    updateRequestState(*connection);
  }
  tcp_recved(pcb, p->tot_len);
  pbuf_free(p);
  return ERR_OK;
}

err_t HttpServer::onSent(void* arg, struct tcp_pcb*, u16_t) {
  Connection* connection = static_cast<Connection*>(arg);
  if (!connection) return ERR_OK;
  connection->activityAt = nowMs();
  return pump(*connection) ? ERR_OK : ERR_ABRT;
}

err_t HttpServer::onPoll(void* arg, struct tcp_pcb* pcb) {
  Connection* connection = static_cast<Connection*>(arg);
  if (!connection) {
    tcp_abort(pcb);
    return ERR_ABRT;
  }
  const uint32_t idleMs = nowMs() - connection->activityAt;
  if ((connection->phase == Phase::Receiving && idleMs >= kReceiveTimeoutMs) ||
      (connection->phase == Phase::Sending && idleMs >= kSendTimeoutMs)) {
    release(*connection, true);
    return ERR_ABRT;
  }
  return pump(*connection) ? ERR_OK : ERR_ABRT;
}

void HttpServer::onError(void* arg, err_t) {
  // lwIP has already freed the pcb.
  Connection* connection = static_cast<Connection*>(arg);
  if (!connection) return;
  connection->pcb = nullptr;
  connection->phase = Phase::Free;
}

void HttpServer::updateRequestState(Connection& connection) {
  if (connection.overflow) {
    connection.phase = Phase::Ready;
    return;
  }
  if (connection.headerLength == 0) {
    const char* end = strstr(connection.rx, "\r\n\r\n");
    if (!end) return;
    connection.headerLength = static_cast<size_t>(end - connection.rx) + 4;

    const char* line = strstr(connection.rx, "\r\n");
    while (line && line + 2 < connection.rx + connection.headerLength) {
      line += 2;
      const size_t remaining =
          connection.headerLength - static_cast<size_t>(line - connection.rx);
      if (startsWithIgnoreCase(line, remaining, "content-length:")) {
        connection.contentLength =
            strtoul(line + strlen("content-length:"), nullptr, 10);
        break;
      }
      line = strstr(line, "\r\n");
    }
    if (connection.headerLength + connection.contentLength > kRxCapacity) {
      connection.overflow = true;
      connection.phase = Phase::Ready;
      return;
    }
  }
  if (connection.rxLength >= connection.headerLength + connection.contentLength) {
    connection.phase = Phase::Ready;
  }
}

bool HttpServer::parseRequest(Connection& connection, HttpRequest& request) {
  const std::string_view rx(connection.rx, connection.headerLength);
  const size_t lineEnd = rx.find("\r\n");
  const std::string_view line = rx.substr(0, lineEnd);
  const size_t methodEnd = line.find(' ');
  if (methodEnd == std::string_view::npos) return false;
  const size_t targetEnd = line.find(' ', methodEnd + 1);
  if (targetEnd == std::string_view::npos) return false;

  const std::string_view method = line.substr(0, methodEnd);
  const std::string_view target =
      line.substr(methodEnd + 1, targetEnd - methodEnd - 1);
  if (target.empty() || target[0] != '/') return false;

  request._method = method == "GET"    ? HttpMethod::Get
                    : method == "POST" ? HttpMethod::Post
                                       : HttpMethod::Other;
  const size_t queryStart = target.find('?');
  request._path = target.substr(0, queryStart);
  request._query = queryStart == std::string_view::npos
                       ? std::string_view()
                       : target.substr(queryStart + 1);
  request._body = std::string_view(connection.rx + connection.headerLength,
                                   connection.contentLength);
  return true;
}

void HttpServer::poll(RequestHandler handler, void* context) {
  for (size_t i = 0; i < kMaxConnections; ++i) {
    Connection& connection = _connections[i];
    if (connection.phase != Phase::Ready || !connection.pcb) continue;

    HttpRequest request(*this, i);
    if (connection.overflow) {
      request.send(413, "text/plain; charset=utf-8", "Request too large");
      continue;
    }
    if (!parseRequest(connection, request)) {
      request.send(400, "text/plain; charset=utf-8", "Bad request");
      continue;
    }
    handler(context, request);
    if (!request.sent()) {
      request.send(500, "text/plain; charset=utf-8", "No response");
    }
    // Requests can carry Wi-Fi passwords; do not leave them in the buffer.
    memset(connection.rx, 0, sizeof(connection.rx));
    connection.rxLength = 0;
  }
}

void HttpServer::beginResponse(size_t connectionIndex, std::string head,
                               const char* body, size_t bodyLength) {
  Connection& connection = _connections[connectionIndex];
  if (!connection.pcb) return;
  connection.head = std::move(head);
  connection.headSent = 0;
  connection.body = body;
  connection.bodyLength = body ? bodyLength : 0;
  connection.bodySent = 0;
  connection.phase = Phase::Sending;
  connection.activityAt = nowMs();
  pump(connection);
}

bool HttpServer::pump(Connection& connection) {
  if (!connection.pcb || connection.phase != Phase::Sending) return true;

  while (true) {
    const char* data = nullptr;
    size_t remaining = 0;
    u8_t flags = 0;
    if (connection.headSent < connection.head.size()) {
      data = connection.head.data() + connection.headSent;
      remaining = connection.head.size() - connection.headSent;
      flags = TCP_WRITE_FLAG_COPY;
    } else if (connection.bodySent < connection.bodyLength) {
      // Static flash bodies are referenced, not copied into RAM.
      data = connection.body + connection.bodySent;
      remaining = connection.bodyLength - connection.bodySent;
    } else {
      break;
    }

    const size_t space = tcp_sndbuf(connection.pcb);
    if (space == 0) break;
    const u16_t chunk = static_cast<u16_t>(std::min(remaining, space));
    const err_t err = tcp_write(connection.pcb, data, chunk, flags);
    if (err == ERR_MEM) break;  // Resumed from the sent/poll callbacks.
    if (err != ERR_OK) return release(connection, true);

    if (connection.headSent < connection.head.size()) {
      connection.headSent += chunk;
    } else {
      connection.bodySent += chunk;
    }
  }
  tcp_output(connection.pcb);

  if (connection.headSent >= connection.head.size() &&
      connection.bodySent >= connection.bodyLength) {
    // Everything is queued; a graceful close still delivers it.
    return release(connection, false);
  }
  return true;
}

bool HttpServer::release(Connection& connection, bool abort) {
  bool alive = true;
  if (connection.pcb) {
    struct tcp_pcb* pcb = connection.pcb;
    tcp_arg(pcb, nullptr);
    tcp_recv(pcb, nullptr);
    tcp_sent(pcb, nullptr);
    tcp_err(pcb, nullptr);
    tcp_poll(pcb, nullptr, 0);
    if (abort || tcp_close(pcb) != ERR_OK) {
      tcp_abort(pcb);
      alive = false;
    }
    connection.pcb = nullptr;
  }
  connection.phase = Phase::Free;
  connection.body = nullptr;
  connection.bodyLength = 0;
  return alive;
}

}  // namespace pico_wifi_portal_detail
