#include "host/FakePico.h"
#include "host/TestAccess.h"

#include "host/TestAssert.h"
#include <cstdint>
#include <iostream>
#include <string>

namespace {

using DisconnectReason = PicoWiFiPortal::DisconnectReason;
using State = PicoWiFiPortal::State;

void seedCredentials(PicoWiFiPortal& portal) {
  assert(PicoWiFiPortalTestAccess::saveCredentials(
      portal, "Test Router", "test-password"));
}

// Schedules a Reconnect and runs it to the point where connect_async() has
// been called. The 20 ms settle step separates the attempt start from the
// connect call. Returns the time the attempt began connecting.
uint32_t beginFirstReconnect(PicoWiFiPortal& portal,
                             uint32_t scheduledAt = 0) {
  FakeMillis = scheduledAt;
  portal.setAutoReconnect(false);
  portal.setAutoReconnect(true);
  const uint32_t before = FakeMillis;
  portal.process();
  assert(FakeMillis == before);
  FakeMillis = scheduledAt + 1000;
  portal.process();
  assert(FakeCyw43.connectCalls == 0);
  FakeMillis += 20;
  portal.process();
  assert(FakeCyw43.connectCalls == 1);
  assert(PicoWiFiPortalTestAccess::reconnectAttemptActive(portal));
  return PicoWiFiPortalTestAccess::connectAttemptAt(portal);
}

void expectFiniteTimeout(uint32_t timeoutMs) {
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    assert(portal.setConnectionRetryPolicy(0, 1000, 60000));
    portal.setConnectTimeout(timeoutMs);
    const uint32_t attemptAt = beginFirstReconnect(portal);

    FakeMillis = attemptAt + timeoutMs - 1;
    const uint32_t before = FakeMillis;
    portal.process();
    assert(FakeMillis == before);
    assert(PicoWiFiPortalTestAccess::reconnectAttemptActive(portal));

    FakeMillis = attemptAt + timeoutMs;
    portal.process();
    assert(!PicoWiFiPortalTestAccess::reconnectAttemptActive(portal));
    assert(PicoWiFiPortalTestAccess::reconnectScheduled(portal));
    assert(PicoWiFiPortalTestAccess::reconnectDelay(portal) == 60000);
  }
}

// A link that reports a terminal CYW43 status (NONET/FAIL) ends a Reconnect
// attempt on the next process() call instead of waiting for the timeout.
void expectReconnectEndsEarly(int linkStatus, DisconnectReason reason) {
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    assert(portal.setConnectionRetryPolicy(0, 1000, 60000));
    portal.setConnectTimeout(15000);
    const uint32_t attemptAt = beginFirstReconnect(portal);

    FakeMillis = attemptAt + 5;
    FakeCyw43.linkStatus = linkStatus;
    portal.process();
    assert(!PicoWiFiPortalTestAccess::reconnectAttemptActive(portal));
    assert(PicoWiFiPortalTestAccess::reconnectScheduled(portal));
    assert(PicoWiFiPortalTestAccess::reconnectDelay(portal) == 60000);
    assert(portal.lastDisconnectReason() == reason);
  }
}

// Same for a blocking connectSaved(): the attempt fails within a few
// milliseconds, not after the 15 s connect timeout.
void expectBlockingEndsEarly(int linkStatusAfterConnect,
                             DisconnectReason reason) {
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    portal.setAutoReconnect(false);
    FakeCyw43.linkStatusAfterConnect = linkStatusAfterConnect;
    const uint32_t startedAt = FakeMillis;
    assert(!portal.connectSaved(15000));
    assert(FakeMillis - startedAt < 100);
    assert(FakeCyw43.connectCalls == 1);
    assert(portal.lastDisconnectReason() == reason);
    assert(portal.state() == State::Failed);
  }
}

// The link comes up on the first STA status read after
// cyw43_arch_wifi_connect_async(). In connect() and processAutoReconnect() that
// read is the success check (isConnected()), so the library must record UP
// there instead of keeping the JOIN it set before connecting.
void armLinkUpOnFirstReadAfterConnect() {
  FakeCyw43.onLinkStatus = []() {
    if (FakeCyw43.connectCalls == 1 &&
        FakeCyw43.linkStatus == CYW43_LINK_JOIN) {
      fakeLinkUp();
    }
  };
}

}  // namespace

int main() {
  // Finite connect timeouts end a Reconnect attempt exactly at the deadline.
  expectFiniteTimeout(10000);
  expectFiniteTimeout(15000);

  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    portal.setConnectTimeout(0);
    assert(PicoWiFiPortalTestAccess::connectTimeout(portal) == 15000);
    seedCredentials(portal);
    assert(portal.setConnectionRetryPolicy(0, 1000, 60000));
    const uint32_t attemptAt = beginFirstReconnect(portal);
    FakeMillis = attemptAt + 14999;
    portal.process();
    assert(PicoWiFiPortalTestAccess::reconnectAttemptActive(portal));
    FakeMillis = attemptAt + 15000;
    portal.process();
    assert(!PicoWiFiPortalTestAccess::reconnectAttemptActive(portal));
    assert(PicoWiFiPortalTestAccess::reconnectDelay(portal) == 60000);
  }

  // A blocking connectSaved(0) uses the 15 s default and makes one connect.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    portal.setAutoReconnect(false);
    const uint32_t startedAt = FakeMillis;
    assert(!portal.connectSaved(0));
    const uint32_t elapsed = FakeMillis - startedAt;
    assert(elapsed >= 15000);
    assert(elapsed < 15100);
    assert(FakeCyw43.connectCalls == 1);
    assert(portal.state() == State::Failed);
  }

  // Retry burst -> capped cooldown -> successful reconnect with onConnected
  // called exactly once.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    assert(portal.setConnectionRetryPolicy(1, 1000, 60000));
    portal.setConnectTimeout(10000);
    uint32_t attemptAt = beginFirstReconnect(portal);

    FakeMillis = attemptAt + 10000;
    portal.process();
    assert(PicoWiFiPortalTestAccess::reconnectScheduled(portal));
    assert(PicoWiFiPortalTestAccess::reconnectRetriesUsed(portal) == 1);
    assert(PicoWiFiPortalTestAccess::reconnectDelay(portal) == 1000);

    FakeMillis += 1000;
    portal.process();
    portal.process();
    assert(FakeCyw43.connectCalls == 2);
    attemptAt = PicoWiFiPortalTestAccess::connectAttemptAt(portal);
    FakeMillis = attemptAt + 10000;
    portal.process();
    assert(PicoWiFiPortalTestAccess::reconnectScheduled(portal));
    assert(PicoWiFiPortalTestAccess::reconnectRetriesUsed(portal) == 0);
    assert(PicoWiFiPortalTestAccess::reconnectDelay(portal) == 60000);

    int connectedCallbacks = 0;
    portal.onConnected([&connectedCallbacks]() { ++connectedCallbacks; });
    FakeMillis += 60000;
    portal.process();
    portal.process();
    assert(FakeCyw43.connectCalls == 3);
    fakeLinkUp();
    portal.process();
    assert(portal.state() == State::Connected);
    assert(!PicoWiFiPortalTestAccess::reconnectScheduled(portal));
    assert(connectedCallbacks == 1);
    portal.process();
    assert(connectedCallbacks == 1);
  }

  // retryDelay(): exponential growth from the interval, capped at the maximum.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(portal.setConnectionRetryPolicy(7, 1000, 60000));
    const uint32_t expected[] = {1000, 2000, 4000, 8000,
                                 16000, 32000, 60000, 60000};
    for (uint8_t retry = 1; retry <= 8; ++retry) {
      assert(PicoWiFiPortalTestAccess::retryDelay(portal, retry) ==
             expected[retry - 1]);
    }

    assert(portal.setConnectionRetryPolicy(4, 1000, 5000));
    assert(PicoWiFiPortalTestAccess::retryDelay(portal, 1) == 1000);
    assert(PicoWiFiPortalTestAccess::retryDelay(portal, 2) == 2000);
    assert(PicoWiFiPortalTestAccess::retryDelay(portal, 3) == 4000);
    assert(PicoWiFiPortalTestAccess::retryDelay(portal, 4) == 5000);
    assert(PicoWiFiPortalTestAccess::retryDelay(portal, 5) == 5000);

    assert(portal.setConnectionRetryPolicy(3, 250, 1000));
    assert(PicoWiFiPortalTestAccess::retryDelay(portal, 1) == 250);
    assert(PicoWiFiPortalTestAccess::retryDelay(portal, 2) == 500);
    assert(PicoWiFiPortalTestAccess::retryDelay(portal, 3) == 1000);
    assert(PicoWiFiPortalTestAccess::retryDelay(portal, 4) == 1000);
  }

  // setConnectionRetryPolicy() validation; a rejected policy changes nothing.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    assert(portal.setConnectionRetryPolicy(2, 1000, 8000));
    assert(!portal.setConnectionRetryPolicy(3, 249, 8000));
    assert(portal.lastError() ==
           "Retry interval must be >= 250 ms and maximum >= 1000 ms");
    assert(!portal.setConnectionRetryPolicy(3, 1000, 999));
    assert(!portal.setConnectionRetryPolicy(3, 4000, 2000));
    assert(PicoWiFiPortalTestAccess::retryDelay(portal, 2) == 2000);
    assert(PicoWiFiPortalTestAccess::retryDelay(portal, 4) == 8000);

    assert(portal.setConnectionRetryPolicy(0, 250, 1000));
    assert(portal.setConnectionRetryPolicy(255, 1000, 1000));
    assert(portal.lastError().empty());
  }

  // A drop from Connected is a LinkLost event that schedules a reconnect.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    FakeCyw43.linkStatusAfterConnect = CYW43_LINK_UP;
    assert(portal.connectSaved(15000));
    assert(portal.state() == State::Connected);
    // Let the library observe the link coming up before it drops.
    portal.process();
    assert(FakeCyw43.connectCalls == 1);
    assert(!PicoWiFiPortalTestAccess::reconnectScheduled(portal));

    FakeCyw43.linkStatus = CYW43_LINK_DOWN;
    portal.process();
    assert(portal.lastDisconnectReason() == DisconnectReason::LinkLost);
    assert(PicoWiFiPortalTestAccess::reconnectScheduled(portal));
    assert(PicoWiFiPortalTestAccess::reconnectDelay(portal) == 1000);
    assert(portal.state() == State::Connecting);

    FakeMillis += 1000;
    portal.process();
    portal.process();
    assert(FakeCyw43.connectCalls == 2);
    fakeLinkUp();
    portal.process();
    assert(portal.state() == State::Connected);
  }

  // A local leave is LeftByRequest and must not schedule a reconnect.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    FakeCyw43.linkStatusAfterConnect = CYW43_LINK_UP;
    assert(portal.connectSaved(15000));
    portal.process();

    const uint32_t leaveCalls = FakeCyw43.leaveCalls;
    assert(portal.eraseCredentials(true));
    assert(FakeCyw43.leaveCalls == leaveCalls + 1);
    portal.process();
    assert(portal.lastDisconnectReason() == DisconnectReason::LeftByRequest);
    assert(!PicoWiFiPortalTestAccess::reconnectScheduled(portal));
    assert(portal.state() == State::Idle);

    FakeMillis += 60000;
    portal.process();
    assert(FakeCyw43.connectCalls == 1);
    assert(!PicoWiFiPortalTestAccess::connectAttemptActive(portal));
  }

  // NONET and FAIL end an attempt immediately, both for Reconnect and for
  // blocking connectSaved().
  expectReconnectEndsEarly(CYW43_LINK_NONET, DisconnectReason::NetworkNotFound);
  expectReconnectEndsEarly(CYW43_LINK_FAIL, DisconnectReason::JoinFailed);
  expectBlockingEndsEarly(CYW43_LINK_NONET, DisconnectReason::NetworkNotFound);
  expectBlockingEndsEarly(CYW43_LINK_FAIL, DisconnectReason::JoinFailed);

  // BADAUTH during Reconnect is ambiguous: it enters the capped cooldown and
  // the next attempt can still succeed.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    assert(portal.setConnectionRetryPolicy(0, 1000, 60000));
    const uint32_t attemptAt = beginFirstReconnect(portal);

    FakeMillis = attemptAt + 5;
    FakeCyw43.linkStatus = CYW43_LINK_BADAUTH;
    portal.process();
    assert(portal.lastDisconnectReason() == DisconnectReason::AuthFailed);
    assert(!PicoWiFiPortalTestAccess::reconnectAttemptActive(portal));
    assert(PicoWiFiPortalTestAccess::reconnectScheduled(portal));
    assert(PicoWiFiPortalTestAccess::reconnectDelay(portal) == 60000);
    assert(portal.state() == State::Connecting);

    FakeMillis = attemptAt + 5 + 60000;
    portal.process();
    portal.process();
    assert(FakeCyw43.connectCalls == 2);
    fakeLinkUp();
    portal.process();
    assert(portal.state() == State::Connected);
  }

  // BADAUTH for a blocking connectSaved() is terminal: no retry, and the
  // error names the authentication failure.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    portal.setAutoReconnect(false);
    assert(portal.setConnectionRetryPolicy(3, 1000, 60000));
    FakeCyw43.linkStatusAfterConnect = CYW43_LINK_BADAUTH;
    assert(!portal.connectSaved(15000));
    assert(portal.lastError() == "Wi-Fi authentication failed");
    assert(portal.lastDisconnectReason() == DisconnectReason::AuthFailed);
    assert(FakeCyw43.connectCalls == 1);
    assert(portal.state() == State::Failed);
  }

  // A blocking connect succeeds when the link comes up during cyw43 polling.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    int connectedCallbacks = 0;
    portal.onConnected([&connectedCallbacks]() { ++connectedCallbacks; });
    FakeCyw43.onPoll = []() {
      if (FakeCyw43.connectCalls == 1 &&
          FakeCyw43.linkStatus == CYW43_LINK_JOIN) {
        fakeLinkUp();
      }
    };
    assert(portal.connectSaved(15000));
    assert(connectedCallbacks == 1);
    assert(portal.state() == State::Connected);
    assert(portal.localIP() == PicoWiFiPortal::IPv4Address(192, 168, 1, 50));
    assert(FakeMillis < 100);
    assert(FakeCyw43.connectCalls == 1);
  }

  // A failed connectSaved() schedules saved-connection recovery when auto
  // reconnect is enabled.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    FakeCyw43.linkStatusAfterConnect = CYW43_LINK_NONET;
    assert(!portal.connectSaved(1000));
    assert(PicoWiFiPortalTestAccess::reconnectScheduled(portal));
    assert(PicoWiFiPortalTestAccess::reconnectDelay(portal) == 1000);
    assert(PicoWiFiPortalTestAccess::reconnectRetriesUsed(portal) == 0);
    assert(portal.state() == State::Connecting);

    FakeCyw43.linkStatusAfterConnect = CYW43_LINK_JOIN;
    FakeMillis += 1000;
    portal.process();
    portal.process();
    assert(FakeCyw43.connectCalls == 2);
    assert(PicoWiFiPortalTestAccess::reconnectAttemptActive(portal));
  }

  // setAutoReconnect(false) cancels a scheduled reconnect and sets Idle.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    portal.setAutoReconnect(true);
    assert(PicoWiFiPortalTestAccess::reconnectScheduled(portal));
    assert(portal.state() == State::Connecting);

    portal.setAutoReconnect(false);
    assert(!portal.autoReconnectEnabled());
    assert(!PicoWiFiPortalTestAccess::reconnectScheduled(portal));
    assert(portal.state() == State::Idle);
    FakeMillis = 5000;
    portal.process();
    assert(FakeCyw43.connectCalls == 0);
  }

  // setAutoReconnect(false) during an active Reconnect leaves the STA
  // interface and returns to Idle.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    const uint32_t attemptAt = beginFirstReconnect(portal);
    assert(attemptAt == 1020);
    const uint32_t leaveCalls = FakeCyw43.leaveCalls;

    portal.setAutoReconnect(false);
    assert(!portal.autoReconnectEnabled());
    assert(FakeCyw43.leaveCalls == leaveCalls + 1);
    assert(!PicoWiFiPortalTestAccess::connectAttemptActive(portal));
    assert(!PicoWiFiPortalTestAccess::reconnectScheduled(portal));
    assert(portal.state() == State::Idle);
  }

  // uint32 millis wrap: scheduling, the 20 ms settle step and the timeout
  // all work across the wrap point.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    assert(portal.setConnectionRetryPolicy(0, 1000, 60000));
    portal.setConnectTimeout(10000);

    const uint32_t scheduledAt = UINT32_MAX - 500U;
    FakeMillis = scheduledAt;
    portal.setAutoReconnect(false);
    portal.setAutoReconnect(true);
    FakeMillis = 498;
    portal.process();
    assert(FakeCyw43.connectCalls == 0);
    FakeMillis = 499;
    portal.process();
    FakeMillis = 519;
    portal.process();
    assert(FakeCyw43.connectCalls == 1);

    const uint32_t attemptAt = PicoWiFiPortalTestAccess::connectAttemptAt(portal);
    FakeMillis = attemptAt + 9999U;
    portal.process();
    assert(PicoWiFiPortalTestAccess::reconnectAttemptActive(portal));
    FakeMillis = attemptAt + 10000U;
    portal.process();
    assert(!PicoWiFiPortalTestAccess::reconnectAttemptActive(portal));
    assert(PicoWiFiPortalTestAccess::reconnectScheduled(portal));
  }

  // Bug 1: a link that came up during the success check of a blocking
  // connectSaved() must still be seen as a drop from UP (LinkLost).
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    armLinkUpOnFirstReadAfterConnect();
    assert(portal.connectSaved(15000));
    assert(FakeCyw43.connectCalls == 1);
    assert(portal.state() == State::Connected);

    FakeCyw43.linkStatus = CYW43_LINK_DOWN;
    FakeMillis += 5;
    portal.process();
    assert(portal.lastDisconnectReason() == DisconnectReason::LinkLost);
    assert(PicoWiFiPortalTestAccess::reconnectScheduled(portal));
    assert(portal.state() == State::Connecting);
  }

  // Bug 1: the same for a successful auto-reconnect attempt.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    assert(portal.setConnectionRetryPolicy(0, 1000, 60000));
    armLinkUpOnFirstReadAfterConnect();
    portal.setAutoReconnect(false);
    portal.setAutoReconnect(true);
    FakeMillis = 1000;
    portal.process();
    FakeMillis = 1020;
    portal.process();
    assert(FakeCyw43.connectCalls == 1);
    assert(!PicoWiFiPortalTestAccess::reconnectAttemptActive(portal));
    assert(portal.state() == State::Connected);

    FakeCyw43.linkStatus = CYW43_LINK_DOWN;
    FakeMillis += 5;
    portal.process();
    assert(portal.lastDisconnectReason() == DisconnectReason::LinkLost);
    assert(PicoWiFiPortalTestAccess::reconnectScheduled(portal));
    assert(portal.state() == State::Connecting);
  }

  // Bug 3: a blocking attempt that ends on NONET/FAIL reports the join result,
  // not a connect timeout. A plain timeout keeps the timeout message.
  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    portal.setAutoReconnect(false);
    assert(portal.setConnectionRetryPolicy(0, 1000, 60000));
    FakeCyw43.linkStatusAfterConnect = CYW43_LINK_NONET;
    assert(!portal.connectSaved(15000));
    assert(portal.lastError() == "Wi-Fi network not found");
    assert(portal.lastDisconnectReason() == DisconnectReason::NetworkNotFound);
  }

  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    portal.setAutoReconnect(false);
    assert(portal.setConnectionRetryPolicy(0, 1000, 60000));
    FakeCyw43.linkStatusAfterConnect = CYW43_LINK_FAIL;
    assert(!portal.connectSaved(15000));
    assert(portal.lastError() == "Wi-Fi join failed");
    assert(portal.lastDisconnectReason() == DisconnectReason::JoinFailed);
  }

  resetFakeRuntime();
  {
    PicoWiFiPortal portal;
    portal.setLogging(false);
    seedCredentials(portal);
    portal.setAutoReconnect(false);
    assert(portal.setConnectionRetryPolicy(0, 1000, 60000));
    portal.setConnectTimeout(3000);
    FakeCyw43.linkStatusAfterConnect = CYW43_LINK_JOIN;
    assert(!portal.connectSaved(3000));
    assert(portal.lastError() == "Wi-Fi connection timed out");
    assert(portal.lastDisconnectReason() == DisconnectReason::None);
  }

  std::cout << "Finite reconnect timeout, retry, cooldown, link event and wrap tests passed\n";
  return 0;
}
