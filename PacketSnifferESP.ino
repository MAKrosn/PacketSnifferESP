#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>

const char* ssid = "NETIASPOT-2.4GHz-8Uys";
const char* password = "dsX6828a";

// IEEE 802.11 MAC Header (24 bytes)
struct IEEE80211MacHeader {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  dest_addr[6];
    uint8_t  source_addr[6];
    uint8_t  bssid[6];
    uint16_t sequence_control;
} __attribute__((packed));

// Fixed fields in the Beacon frame (12 bytes)
struct BeaconFixedFields {
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities;
} __attribute__((packed));

// SSID element
struct SSIDElement {
    uint8_t element_id;  // SSID parameter set (0)
    uint8_t length;
    char ssid[32];  // Placeholder for up to 32-byte SSID
} __attribute__((packed));

// Supported Rates element
struct SupportedRatesElement {
    uint8_t element_id;  // Supported Rates ID (usually 0x01)
    uint8_t length;  // Number of rates listed
    uint8_t rates[8];  // Supported rates, up to 8 for the beacon frame
} __attribute__((packed));

// Complete Beacon frame
struct BeaconFrame {
    IEEE80211MacHeader mac_header;
    BeaconFixedFields fixed_fields;
    SSIDElement ssid_element;
    SupportedRatesElement supported_rates_element;
    //uint8_t element_id;
} __attribute__((packed));

typedef struct {
    unsigned frame_ctrl:16;
    unsigned duration_id:16;
    uint8_t dest[6]; // receiver address
    uint8_t src[6]; // sender address
    uint8_t addr3[6]; // filtering address
    unsigned sequence_ctrl:16;
    uint8_t addr4[6]; // optional
} wifi_ieee80211_mac_hdr_t;

typedef struct {
    wifi_ieee80211_mac_hdr_t hdr;
    uint8_t payload[0]; // network data ended with 4 bytes csum (CRC32)
} wifi_ieee80211_packet_t;

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {

  if (type != WIFI_PKT_MGMT)
    return;


  
  const auto ppkt = (wifi_promiscuous_pkt_t*)buff;
  const wifi_ieee80211_packet_t* ipkt = (wifi_ieee80211_packet_t*)ppkt->payload;
  if(ipkt->hdr.frame_ctrl != 0x0080) return;
  const auto beaconFrame = (BeaconFrame&)*ipkt;
  
  //Serial.print("RSSI: ");
  //Serial.print(ppkt->rx_ctrl.rssi, DEC);

  Serial.print(" SRC: ");
  printMacAddress(beaconFrame.mac_header.source_addr);

  Serial.print(" DST: ");
  printMacAddress(beaconFrame.mac_header.dest_addr);

  Serial.print(" BSSID: ");
  printMacAddress(beaconFrame.mac_header.bssid);
  
  Serial.print(" Sequence Control: ");
  Serial.print(beaconFrame.mac_header.sequence_control, HEX);
  
  Serial.print(" Capabilities: ");
  Serial.print(beaconFrame.fixed_fields.capabilities, HEX);

  Serial.print(" Timestamp: ");
  Serial.print((uint32_t)(beaconFrame.fixed_fields.timestamp & 0xFFFFFFFF), HEX);  // Lower 32 bits of timestamp
  Serial.print((uint32_t)(beaconFrame.fixed_fields.timestamp >> 32), HEX);        // Upper 32 bits of timestamp

  Serial.print(" SSID: ");
  std::string ssid(beaconFrame.ssid_element.ssid, beaconFrame.ssid_element.length);
  Serial.print(ssid.c_str());

  Serial.println();

  Serial.print(" SSID: ");
  Serial.print(ssid.c_str());
  Serial.println();
  auto supRates = *((SupportedRatesElement*)beaconFrame.ssid_element.ssid + beaconFrame.ssid_element.length);
  Serial.print(supRates.element_id);
  Serial.println();
  Serial.print((uint8_t)*(supRates.rates + supRates.length));
  Serial.println();
}

void printMacAddress(const uint8_t mac[6]) {
  for (int i = 0; i < 6; i++) {
    Serial.print(mac[i], HEX);
    if (i < 5)
      Serial.print(":");
  }
}

void setup() {

  Serial.begin(115200);

  WiFi.mode(WIFI_MODE_STA);
  WiFi.disconnect();

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);

}

void loop() {
  delay(1000);
}
