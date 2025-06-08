#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <IPAddress.h>
#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/ip.h"
#include "lwip/init.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include <Crypto.h>
#include <Curve25519.h>
#include <RNG.h>
#include <string.h>
#include <ESP8266mDNS.h>
extern "C" {
#include "wireguardif.h"
#include "wireguard-platform.h"
}

static uint8_t m_publicKey[32];
static uint8_t m_privateKey[32];

static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL;
static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
IPAddress ipaddr(1, 2, 3, 4);
IPAddress netmask(255, 255, 255, 0);
IPAddress gw(1,2,3,4);
//IPAddress dns1(8, 8, 8, 8);

const char* private_key = "REDACTED";
const char* public_key = "REDACTED"; // server's pubkey
int endpoint_port = 51820;              // [Peer] Endpoint


// Replace with your network credentials
const char* ssid = "REDACTED"; 
const char* password = "REDACTED"; 

String HTMLpage = "";
int relay = 0;


class WireGuard
{
  public:
    void begin();
     private:
       void wg_netif_set_ipaddr(struct netif *data, uint32_t addr);
       void wg_netif_set_netmask(struct netif *data, uint32_t addr);
       void wg_netif_set_gw(struct netif *data, uint32_t addr);
       void wg_netif_set_up(struct netif *data);
  private:
    void wg_if_add_dns(uint32_t addr);
    void wg_if_clear_dns(void);
};

void ICACHE_FLASH_ATTR
WireGuard::wg_netif_set_ipaddr(struct netif *data, uint32_t addr)
{
 ip_addr_t ipaddr;
 ipaddr.addr = addr;
 netif_set_ipaddr(data, &ipaddr);
}

void ICACHE_FLASH_ATTR
WireGuard::wg_netif_set_netmask(struct netif *data, uint32_t addr)
{
 ip_addr_t ipaddr;
 ipaddr.addr = addr;
 netif_set_netmask(data, &ipaddr);
}

void ICACHE_FLASH_ATTR
WireGuard::wg_netif_set_gw(struct netif *data, uint32_t addr)
{
 ip_addr_t ipaddr;
 ipaddr.addr = addr;
 netif_set_gw(data, &ipaddr);
}

void ICACHE_FLASH_ATTR
WireGuard::wg_netif_set_up(struct netif *data)
{
 netif_set_up(data);
}

static int dns_count;

void ICACHE_FLASH_ATTR
WireGuard::wg_if_clear_dns(void)
{
  ip_addr_t addr;
  //  addr.addr = INADDR_ANY;
  int i;
  for (i = 0; i < DNS_MAX_SERVERS; i++)
    dns_setserver(i, &addr);
  dns_count = 0;
}

void ICACHE_FLASH_ATTR
WireGuard::wg_if_add_dns(uint32_t addr)
{
  ip_addr_t ipaddr;
#ifdef ESP8266
  ipaddr.addr = addr;
#else
  ipaddr.u_addr.ip4.addr = addr;
#endif
  dns_setserver(dns_count++, &ipaddr);
}

void WireGuard::begin() {
  struct wireguardif_init_data wg;
  struct wireguardif_peer peer;
  ip_addr_t _ipaddr = IPADDR4_INIT(static_cast<uint32_t>(ipaddr));
  ip_addr_t _netmask = IPADDR4_INIT(static_cast<uint32_t>(netmask));
  ip_addr_t _gateway = IPADDR4_INIT(static_cast<uint32_t>(gw));
  // Setup the WireGuard device structure
  wg.private_key = private_key;
  wg.listen_port = endpoint_port;
  wg.bind_netif = NULL;// if ethernet use eth netif
  // Initialise the first WireGuard peer structure
  wireguardif_peer_init(&peer);
  // Register the new WireGuard network interface with lwIP

   wg_netif = netif_add(&wg_netif_struct, NULL, NULL, NULL, &wg, &wireguardif_init, &ip_input);
   wg_netif_set_ipaddr(wg_netif, ipaddr);
   wg_netif_set_netmask(wg_netif, netmask);
   wg_netif_set_gw(wg_netif, gw);

  wg_netif = netif_add(&wg_netif_struct, ip_2_ip4(&_ipaddr), ip_2_ip4(&_netmask), ip_2_ip4(&_gateway), &wg, &wireguardif_init, &ip_input);

  if ( wg_netif == nullptr ) {
    Serial.println("failed to initialize WG netif.");
    return;
  }
  // Mark the interface as administratively up, link up flag is set automatically when peer connects
  //wg_netif_set_up(wg_netif); // alternate netif
  netif_set_up(wg_netif);
  //wg_if_add_dns(dns1);

  peer.public_key = public_key;
  peer.preshared_key = NULL;
  // Allow all IPs through tunnel
  //  peer.allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
  //  peer.allowed_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);
  {
    ip_addr_t allowed_ip = IPADDR4_INIT_BYTES(1, 2, 3, 4);
    peer.allowed_ip = allowed_ip;
    ip_addr_t allowed_mask = IPADDR4_INIT_BYTES(255, 255, 255, 0);
    peer.allowed_mask = allowed_mask;
  }
  IPAddress IP;
  WiFi.hostByName("REDACTED", IP);
  Serial.println(IP[0]);
  // If we know the endpoint's address can add here
  peer.endpoint_ip = IPADDR4_INIT_BYTES(IP[0], IP[1], IP[2], IP[3]);
  peer.endport_port = endpoint_port;

  // Register the new WireGuard peer with the netwok interface
  wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index);

  if ((wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip)) {
    // Start outbound connection to peer
    wireguardif_connect(wg_netif, wireguard_peer_index);

    //delay(100);
    netif_set_default(wg_netif);
    Serial.println("wireguard start completed");
  } else if (wireguard_peer_index == WIREGUARDIF_INVALID_INDEX) {
    Serial.println("wireguard if invalid index");
  } else if (ip_addr_isany(&peer.endpoint_ip)) {
    Serial.println("wireguard endpoint ip not found");
  }
}

static WireGuard wg;
#ifdef ESP8266
ESP8266WebServer server(80);
#else
WebServer server(80);
#endif
static const char *base64_lookup = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void handleRoot() {
  digitalWrite(relay, 1);
  server.send(200, "text/plain", "hello from esp8266!");
  digitalWrite(relay, 0);
}

void handleNotFound() {
  digitalWrite(relay, 1);
  String message = "File Not Found\n\n";
  message += "URI: ";
  message += server.uri();
  message += "\nMethod: ";
  message += (server.method() == HTTP_GET) ? "GET" : "POST";
  message += "\nArguments: ";
  message += server.args();
  message += "\n";
  for (uint8_t i = 0; i < server.args(); i++) {
    message += " " + server.argName(i) + ": " + server.arg(i) + "\n";
  }
  server.send(404, "text/plain", message);
  digitalWrite(relay, 0);
}

void setup(void) {
  //WireGuard wg;
  HTMLpage += "<head><title>Light Webserver</title></head><h3>ESP8266 Webserver (Toggle Relay)</h3><p>led <a href=\"on\"><button>ON</button></a> <a href=\"off\"><button>OFF</button></a></p>";
  pinMode(relay, OUTPUT);
  digitalWrite(relay, LOW);
  Serial.begin(115200);
  WiFi.mode(WIFI_STA); 
  WiFi.begin(ssid,password);
  Serial.println("");

  // Wait for connection
  
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("");
  Serial.print("Connected to ");
  Serial.println(ssid);
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());

  if (MDNS.begin("esp8266", WiFi.localIP())) {
    Serial.println("MDNS responder started");
  }

  

  /* If the device is behind NAT or stateful firewall, set persistent_keepalive.
    persistent_keepalive is disabled by default */
  // wg_config.persistent_keepalive = 10;
  wg.begin();
server.on("/", []() {
    server.send(200, "text/html", HTMLpage);
  });
  server.on("/on", []() {
    server.send(200, "text/html", HTMLpage + "<p>Lights are fucking on!</p>");
    digitalWrite(relay, LOW);
    delay(1000);
  });
  server.on("/off", []() {
    server.send(200, "text/html", HTMLpage + "<p>Lights are dim and off, like my esp8266 soul :(</p>");
    digitalWrite(relay, HIGH);
    delay(1000);
  });

  server.begin();
  Serial.println("HTTP Webserver started");

}

void loop(void) {
  server.handleClient();
}
