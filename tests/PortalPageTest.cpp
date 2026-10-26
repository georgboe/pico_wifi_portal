#include "host/FakePico.h"

#include <PicoWiFiPortal.h>
#include "host/TestAccess.h"
#include <PortalPage.h>

#include "host/TestAssert.h"
#include <iostream>
#include <string>

namespace {

std::string formBody(const std::string& ssid, const std::string& password) {
  // Form values are percent-encoded: spaces and quotes would otherwise break
  // the urlencoded body.
  static const char kHex[] = "0123456789ABCDEF";
  auto encode = [](const std::string& value) {
    std::string encoded;
    for (const unsigned char character : value) {
      const bool unreserved = (character >= 'A' && character <= 'Z') ||
                              (character >= 'a' && character <= 'z') ||
                              (character >= '0' && character <= '9') ||
                              character == '-' || character == '_' ||
                              character == '.' || character == '~';
      if (unreserved) {
        encoded += static_cast<char>(character);
      } else {
        encoded += '%';
        encoded += kHex[character >> 4];
        encoded += kHex[character & 0x0F];
      }
    }
    return encoded;
  };
  return "ssid=" + encode(ssid) + "&password=" + encode(password);
}

void expectSaveValidation(const std::string& ssid,
                          const std::string& password,
                          int expectedStatus,
                          const std::string& expectedSSID = std::string()) {
  resetFakeRuntime();
  PicoWiFiPortal portal;
  portal.setLogging(false);
  assert(portal.startConfigPortalAsync("Portal-Test", "12345678"));
  FakeHttpResponse first =
      httpRequest(portal, "POST", "/save", formBody(ssid, password));
  assert(first.status == expectedStatus);
  if (expectedStatus == 200) {
    assert(first.headers["Content-Type"] == "text/html; charset=utf-8");
    assert(first.body == std::string(PWP_CONNECTING_HTML));
    assert(PicoWiFiPortalTestAccess::pendingSSID(portal) == expectedSSID);
    assert(PicoWiFiPortalTestAccess::pendingPassword(portal) == password);
    FakeHttpResponse second =
        httpRequest(portal, "POST", "/save", formBody(ssid, password));
    assert(second.status == 409);
  } else {
    // Rejected credentials are wiped and never reach the connection state.
    assert(PicoWiFiPortalTestAccess::pendingSSID(portal).empty());
    assert(PicoWiFiPortalTestAccess::pendingPassword(portal).empty());
    assert(!PicoWiFiPortalTestAccess::connectPending(portal));
  }
  portal.stopConfigPortal();
}

void expectPortalPage(const std::string& path) {
  resetFakeRuntime();
  PicoWiFiPortal portal;
  portal.setLogging(false);
  assert(portal.startConfigPortalAsync("Portal-Test", "12345678"));
  FakeHttpResponse response = httpRequest(portal, "GET", path);
  assert(response.status == 200);
  assert(response.headers["Content-Type"] == "text/html; charset=utf-8");
  assert(response.body == std::string(PWP_PORTAL_HTML));
  portal.stopConfigPortal();
}

size_t countOccurrences(const std::string& value,
                        const std::string& expected) {
  size_t count = 0;
  size_t position = 0;
  while ((position = value.find(expected, position)) != std::string::npos) {
    ++count;
    position += expected.length();
  }
  return count;
}

}  // namespace

int main() {
  const std::string page(PWP_PORTAL_HTML);
  assert(page.find("id=\"advancedLink\" href=\"#advanced\">More Wi-Fi settings</a>") !=
         std::string::npos);
  assert(page.find("id=\"advancedView\"") != std::string::npos);
  assert(page.find("id=\"manualView\"") != std::string::npos);
  assert(page.find("id=\"propertiesView\"") != std::string::npos);
  assert(page.find("id=\"advancedBack\" href=\"#scan\">Back Home Screen</a>") !=
         std::string::npos);
  assert(page.find("id=\"manualButton\" type=\"button\">Manual Configure WiFi</button>") !=
         std::string::npos);
  assert(page.find("id=\"propertiesButton\" type=\"button\">Properties</button>") !=
         std::string::npos);
  assert(page.find("id=\"resetButton\" type=\"button\">Reset</button>") !=
         std::string::npos);
  assert(page.find("id=\"manualBack\" href=\"#advanced\">Back</a>") !=
         std::string::npos);
  assert(page.find("Manual Configure Wi-Fi") != std::string::npos);
  assert(page.find("Network name") != std::string::npos);
  assert(page.find("Password") != std::string::npos);
  assert(page.find(">Connect</button>") != std::string::npos);
  assert(page.find("id=\"propertiesBack\" href=\"#advanced\">Back</a>") !=
         std::string::npos);
  assert(page.find("Properties Device") != std::string::npos);
  // The properties table reports the chip model; the old flash speed row is
  // gone.
  assert(page.find("id=\"propertyChip\"") != std::string::npos);
  assert(page.find("<td>Chip Model</td>") != std::string::npos);
  assert(page.find("Flash Chip Speed") == std::string::npos);

  const size_t advancedStart = page.find("id=\"advancedView\"");
  const size_t manualStart = page.find("id=\"manualView\"");
  assert(advancedStart < manualStart);
  const std::string advancedView =
      page.substr(advancedStart, manualStart - advancedStart);
  assert(advancedView.find("Network name") == std::string::npos);
  assert(countOccurrences(advancedView, "<button") == 3);
  assert(page.find("manualButton.onclick=()=>location.hash='#manual'") !=
         std::string::npos);
  assert(page.find("propertiesButton.onclick=()=>location.hash='#properties'") !=
         std::string::npos);

  assert(page.find("method=\"post\" action=\"/save\"") !=
         std::string::npos);
  assert(page.find("id=\"manualPassword\" name=\"manual-password\" type=\"password\"") !=
         std::string::npos);
  assert(page.find("id=\"manualPassword\" name=\"manual-password\" type=\"password\" maxlength=\"64\"") !=
         std::string::npos);
  assert(page.find("input.maxLength=64") != std::string::npos);
  assert(page.find("^[0-9a-f]{64}$") != std::string::npos);
  assert(page.find("manualReveal.onclick") != std::string::npos);
  assert(page.find("if(submitting)return") != std::string::npos);
  assert(page.find("aria-pressed") != std::string::npos);
  assert(page.find("text-decoration:underline") != std::string::npos);
  assert(page.find("width:36%") != std::string::npos);
  assert(page.find("1.15s linear infinite") != std::string::npos);
  assert(page.find("prefers-reduced-motion:reduce") != std::string::npos);
  assert(page.find("scaleX(") == std::string::npos);
  // The SSID is kept in sessionStorage for the connecting page; the password
  // never is.
  assert(page.find("sessionStorage.setItem('ewpSSID',entry.network.ssid)") !=
         std::string::npos);
  assert(std::string(PWP_CONNECTING_HTML).find(
             "sessionStorage.getItem('ewpSSID')") != std::string::npos);
  assert(page.find("sessionStorage.setItem('ewpPassword") ==
         std::string::npos);
  assert(page.find("localStorage") == std::string::npos);
  assert(page.find("URLSearchParams") == std::string::npos);
  assert(page.find("innerHTML") == std::string::npos);
  assert(page.find("fetch('/properties',{cache:'no-store'})") !=
         std::string::npos);
  assert(page.find("document.getElementById(id).textContent=value") !=
         std::string::npos);
  assert(page.find("fetch('/reset',{method:'POST',cache:'no-store'})") !=
         std::string::npos);
  assert(page.find("showView();\nscan();") == std::string::npos);
  assert(page.find("if(view==='scan'&&!scanInitialized)scan()") !=
         std::string::npos);
  assert(page.find("history.replaceState(null,'','#scan')") !=
         std::string::npos);
  assert(page.find("querySelectorAll('button,input')") ==
         std::string::npos);

  expectPortalPage("/");
  expectPortalPage("/wifi");

  expectSaveValidation(" Hidden SSID ", "", 200, " Hidden SSID ");
  expectSaveValidation(std::string(32, 'S'), std::string(63, 'P'), 200,
                       std::string(32, 'S'));
  expectSaveValidation("Secured", "12345678", 200, "Secured");
  expectSaveValidation("", "", 400);
  expectSaveValidation(std::string(33, 'S'), "12345678", 400);
  expectSaveValidation("Secured", "1234567", 400);
  expectSaveValidation("Secured", std::string(64, 'P'), 400);
  expectSaveValidation("Raw PSK", std::string(64, 'A'), 200, "Raw PSK");
  expectSaveValidation("Secured", std::string(65, 'A'), 400);

  std::cout << "Advanced portal UI and exact credential validation tests passed\n";
  return 0;
}
