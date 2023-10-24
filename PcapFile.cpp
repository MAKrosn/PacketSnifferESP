/**
 * @file PcapFile.cpp
 * @author MAKrosniak (michal@krosniak.it)
 * @date 2023-10-20
 * @copyright Copyright (c) 2023
 *
 * @brief Cpp implementation of PCAP serializer
 */
#include "PcapFile.hpp"

PcapFile::PcapFile(Stream& stream) : Serial(stream)
{
    size = 0;
}

void PcapFile::appendFrame(const uint8_t *buffer, size_t frameSize, uint32_t usecTime)
{
    const uint8_t * bufferEnd = buffer + frameSize;
    if(frameSize > SNAPLEN){
        bufferEnd = buffer + SNAPLEN;
        size = sizeof(PcapRecordHeader) + SNAPLEN;
    }
    else
    {
        size = sizeof(PcapRecordHeader) + frameSize;
    }
    std::vector<uint8_t> frame(buffer, bufferEnd);
    recordsBuffer.emplace_back(PcapRecord{usecTime / 1000000, usecTime % 1000000, frame.size() , frameSize, frame});
}

void PcapFile::directSerialOutput(const uint8_t *buffer, size_t frameSize, uint32_t usecTime)
{
    uint8_t STX = 0x02; // Start of Text
    uint8_t ETX = 0x03; // End of Text

    // Calculate checksum (for demonstration, just summing up bytes)


    if(frameSize > SNAPLEN)
    {
        //bufferEnd = buffer + SNAPLEN;
        size = SNAPLEN;
    }
    else
    {
        size = frameSize;
    }
    size = frameSize;
    // Write STX (Start of Text)
    Serial.write(STX);
    // Write existing data
    size_t dataSize = frameSize + sizeof(PcapRecordHeader);
    Serial.write((uint8_t*)&dataSize, sizeof(size_t));  // Optional: send the frame size first
    Serial.write((uint8_t*)&usecTime, sizeof(uint32_t)); // Optional: send the timestamp first

    PcapRecordHeader frameHeader{usecTime / 1000000, usecTime % 1000000, size, frameSize};
    Serial.write((uint8_t*)&frameHeader, sizeof(PcapRecordHeader));
    Serial.write(buffer, frameSize);
    // Write ETX (End of Text)
    Serial.write(ETX);
    uint8_t checksum = 0;
    auto bufferHeader = (uint8_t*)&frameHeader;
    for (int i = 0; i < sizeof(PcapRecordHeader); ++i) {
        checksum += bufferHeader[i];
    }
    for (int i = 0; i < size; ++i) {
        checksum += buffer[i];
    }
    // Write Checksum
    Serial.write(checksum);
}

void PcapFile::writeHeader()
{
    uint8_t STX = 0x02; // Start of Text
    uint8_t ETX = 0x03; // End of Text
    PcapGlobalHeader globalHeader{PCAP_MAGIC_NUMBER, 2, 4, 0, 0, SNAPLEN, LINKTYPE_IEEE802_11};
    Serial.write(STX);
    // Write existing data
    size_t dataSize = sizeof(PcapGlobalHeader);
    uint32_t usecTime = 0;
    Serial.write((uint8_t*)&dataSize, sizeof(size_t));  // Optional: send the frame size first
    Serial.write((uint8_t*)&usecTime, sizeof(uint32_t)); // Optional: send the timestamp first
    auto buffer = (uint8_t*)&globalHeader;
    uint8_t checksum = 0;
    for (int i = 0; i < sizeof(PcapGlobalHeader); ++i) {
        checksum += buffer[i];
    }
    Serial.write((uint8_t*)&globalHeader, sizeof(PcapGlobalHeader));
    Serial.write(ETX);
    // Write Checksum
    Serial.write(checksum);
}



size_t PcapFile::getBufferSize()
{
    return size;
}

bool PcapFile::writeBufferToSerialOutput()
{
    PcapGlobalHeader globalHeader{PCAP_MAGIC_NUMBER, 2, 4, 0, 0, SNAPLEN, LINKTYPE_IEEE802_11};
    Serial.write((uint8_t*)&globalHeader, sizeof(PcapGlobalHeader));
    for(auto& frame : recordsBuffer)
    {
        Serial.write((uint8_t*)&frame, sizeof(PcapRecordHeader));
        for(auto& byte : frame.data)
        {
            Serial.write(byte);
        }
    }
    return true;
}
