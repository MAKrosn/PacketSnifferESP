#include "PcapFile.hpp"
#include <WiFi.h>
#include <esp_now.h>
#include <esp_wifi.h>
#include <esp_timer.h>

PcapFile pcapFile(Serial);
bool recording = true;
bool writeSerial = false;

void storeFrame(void* buff, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t* ppkt = (wifi_promiscuous_pkt_t*)buff;
    auto packetSize = ppkt->rx_ctrl.sig_len;
    if (type != WIFI_PKT_MGMT || packetSize == 0)
    return;
    if(recording)
      pcapFile.appendFrame((const u_int8_t*)buff, packetSize, esp_timer_get_time());
}

void directWrite(void* buff, wifi_promiscuous_pkt_type_t type) {
  if(writeSerial)
  {
    const wifi_promiscuous_pkt_t* ppkt = (wifi_promiscuous_pkt_t*)buff;
    auto packetSize = ppkt->rx_ctrl.sig_len;
    if (packetSize == 0)
      return;
    pcapFile.directSerialOutput((const u_int8_t*)ppkt->payload, packetSize, esp_timer_get_time());
  }
}

void setup() {

  Serial.begin(115200);
  pinMode(9, INPUT);    // sets the digital pin 7 as input

  WiFi.mode(WIFI_MODE_AP);
  WiFi.disconnect();

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&directWrite);
}

void loop() {
  // if(digitalRead(9) != HIGH) 
  // {
  //   recording = false;
  //   pcapFile.writeBufferToSerialOutput();
  // }
  // delay(100);
  // recording = true;
  if(digitalRead(9) != HIGH)
  {
    pcapFile.writeHeader();
    writeSerial = true;
    delay(120000);
    writeSerial = false;
  }
}