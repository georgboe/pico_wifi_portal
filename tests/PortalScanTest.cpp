#include "host/FakePico.h"

#include <PicoWiFiPortal.h>
#include "host/TestAccess.h"
#include "host/TestAssert.h"
#include <cstdint>
#include <iostream>
#include <string>

namespace {

void startPortal(PicoWiFiPortal& portal) {
  portal.setLogging(false);
  assert(portal.startConfigPortalAsync("Scan-Test", "12345678"));
}

FakeHttpResponse requestScan(PicoWiFiPortal& portal) {
  return httpRequest(portal, "GET", "/scan");
}

size_t countNetworks(const std::string& body) {
  size_t count = 0;
  size_t position = 0;
  while ((position = body.find("\"ssid\":", position)) != std::string::npos) {
    ++count;
    position += 7;
  }
  return count;
}

const char kScanningBody[] = "{\"scanning\":true}";
const char kFailedBody[] = "{\"networks\":[],\"error\":\"Wi-Fi scan failed\"}";
const char kBusyBody[] =
    "{\"networks\":[],\"error\":\"Wi-Fi connection in progress\"}";

}  // namespace

int main() {
  // Deduplication, escaping, sorting, empty/oversized SSIDs and the 202 ->
  // 200 transition.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    startPortal(portal);

    FakeHttpResponse first = requestScan(portal);
    assert(first.status == 202);
    assert(first.headers["Retry-After"] == "1");
    assert(first.headers["Cache-Control"] == "no-store");
    assert(first.body == kScanningBody);
    assert(FakeCyw43.scanCalls == 1);

    // A second poll while the scan runs must not start another scan.
    FakeHttpResponse second = requestScan(portal);
    assert(second.status == 202);
    assert(FakeCyw43.scanCalls == 1);

    fakeScanResult("Strong \"Router\"", -35, 3);
    fakeScanResult("Duplicate", -50, 0);
    fakeScanResult("Duplicate", -80, 3);  // Weaker: ignored.
    fakeScanResult("", -20, 0);           // Empty SSID: ignored.
    fakeScanResult(std::string(33, 'L'), -10, 0);  // Over 32 bytes: ignored.
    fakeScanResult(std::string("Ctl") + char(1) + "X", -60, 3);
    fakeScanResult("Upgrade", -80, 0);
    fakeScanResult("Upgrade", -40, 3);  // Stronger secured AP replaces open.
    fakeScanFinish();

    FakeHttpResponse result = requestScan(portal);
    assert(result.status == 200);
    assert(result.headers["Content-Type"] == "application/json; charset=utf-8");
    assert(result.headers["Cache-Control"] == "no-store");
    assert(result.body ==
           "{\"networks\":["
           "{\"ssid\":\"Strong \\\"Router\\\"\",\"rssi\":-35,\"open\":false},"
           "{\"ssid\":\"Upgrade\",\"rssi\":-40,\"open\":false},"
           "{\"ssid\":\"Duplicate\",\"rssi\":-50,\"open\":true},"
           "{\"ssid\":\"Ctl\\u0001X\",\"rssi\":-60,\"open\":false}"
           "]}");
    // Reading the result does not start a new scan.
    assert(FakeCyw43.scanCalls == 1);
    portal.stopConfigPortal();
  }

  // Start failure reports 503 and leaves the scan idle, so the next poll
  // starts a new scan.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    startPortal(portal);
    FakeCyw43.scanResult = -1;
    FakeHttpResponse failed = requestScan(portal);
    assert(failed.status == 503);
    assert(failed.body == kFailedBody);
    assert(FakeCyw43.scanCalls == 1);

    FakeCyw43.scanResult = 0;
    FakeHttpResponse retry = requestScan(portal);
    assert(retry.status == 202);
    assert(FakeCyw43.scanCalls == 2);
    portal.stopConfigPortal();
  }

  // Timeout across the uint32 millisecond wrap. Late results after the
  // timeout are ignored and do not revive the scan.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    startPortal(portal);
    FakeMillis = UINT32_MAX - 5000U;
    assert(requestScan(portal).status == 202);

    FakeMillis += 14999U;
    assert(requestScan(portal).status == 202);
    assert(FakeCyw43.scanCalls == 1);

    FakeMillis += 1U;
    portal.process();  // Times out without a request.
    fakeScanResult("Late", -10, 0);
    FakeHttpResponse timedOut = requestScan(portal);
    assert(timedOut.status == 503);
    assert(timedOut.body == kFailedBody);
    assert(FakeCyw43.scanCalls == 1);

    assert(requestScan(portal).status == 202);
    assert(FakeCyw43.scanCalls == 2);
    portal.stopConfigPortal();
  }

  // Table full: the strongest kMaxScanResults networks are kept.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    startPortal(portal);
    assert(requestScan(portal).status == 202);

    const size_t capacity = PicoWiFiPortalTestAccess::maxScanResults();
    for (size_t i = 0; i < capacity; ++i) {
      const std::string ssid = "N" + std::string(i < 10 ? "0" : "") +
                               std::to_string(i);
      fakeScanResult(ssid, static_cast<int16_t>(-50 - static_cast<int>(i)), 0);
    }
    fakeScanResult("Weak", -90, 0);  // Weaker than all: dropped.
    fakeScanResult("Tie", -73, 0);   // Equal to the weakest: dropped.
    fakeScanResult("Strong", -40, 0);  // Evicts the weakest, N23.
    fakeScanFinish();

    FakeHttpResponse result = requestScan(portal);
    assert(result.status == 200);
    assert(countNetworks(result.body) == capacity);
    assert(result.body.find("\"ssid\":\"Strong\"") != std::string::npos);
    assert(result.body.find("\"ssid\":\"N22\"") != std::string::npos);
    assert(result.body.find("\"ssid\":\"N23\"") == std::string::npos);
    assert(result.body.find("\"ssid\":\"Weak\"") == std::string::npos);
    assert(result.body.find("\"ssid\":\"Tie\"") == std::string::npos);
    assert(result.body.find("{\"networks\":[{\"ssid\":\"Strong\",\"rssi\":-40,"
                            "\"open\":true},{\"ssid\":\"N00\"") == 0);
    portal.stopConfigPortal();
  }

  // A connection attempt makes /scan return 409 without starting a scan.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    startPortal(portal);
    FakeHttpResponse saved =
        httpRequest(portal, "POST", "/save", "ssid=Router&password=12345678");
    assert(saved.status == 200);
    assert(PicoWiFiPortalTestAccess::connectPending(portal));

    FakeHttpResponse busy = requestScan(portal);
    assert(busy.status == 409);
    assert(busy.headers["Cache-Control"] == "no-store");
    assert(busy.body == kBusyBody);
    assert(FakeCyw43.scanCalls == 0);
    portal.stopConfigPortal();
  }

  // A valid /save resets a scan that is in progress. Shown by the connection
  // attempt failing, after which /scan must start a fresh scan.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    startPortal(portal);
    assert(requestScan(portal).status == 202);
    assert(FakeCyw43.scanCalls == 1);

    FakeHttpResponse saved =
        httpRequest(portal, "POST", "/save", "ssid=Router&password=12345678");
    assert(saved.status == 200);
    // Late result from the reset scan: must be ignored.
    fakeScanResult("Stale", -20, 0);

    FakeCyw43.connectResult = -1;
    FakeMillis += 350U;
    portal.process();  // Starts the connection attempt.
    FakeMillis += 20U;
    portal.process();  // Settle delay over: the join call fails.
    assert(FakeCyw43.connectCalls == 1);
    assert(!PicoWiFiPortalTestAccess::connectPending(portal));
    assert(!PicoWiFiPortalTestAccess::connectAttemptActive(portal));

    FakeHttpResponse retry = requestScan(portal);
    assert(retry.status == 202);
    assert(FakeCyw43.scanCalls == 2);
    portal.stopConfigPortal();
  }

  // stopConfigPortal() discards the scan, and a late result after stop is
  // ignored.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    startPortal(portal);
    assert(requestScan(portal).status == 202);
    portal.stopConfigPortal();
    fakeScanResult("AfterStop", -10, 0);

    startPortal(portal);
    assert(requestScan(portal).status == 202);
    assert(FakeCyw43.scanCalls == 2);
    fakeScanFinish();
    FakeHttpResponse empty = requestScan(portal);
    assert(empty.status == 200);
    assert(empty.body == "{\"networks\":[]}");
    portal.stopConfigPortal();
  }

  std::cout << "Asynchronous scan, deduplication, timeout and cleanup tests passed\n";
  return 0;
}
