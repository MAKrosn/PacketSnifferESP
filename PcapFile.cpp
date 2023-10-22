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
    //const uint8_t * bufferEnd = buffer + frameSize;
    if(frameSize > SNAPLEN)
    {
        //bufferEnd = buffer + SNAPLEN;
        size = SNAPLEN;
    }
    else
    {
        size = frameSize;
    }
    PcapRecordHeader frameHeader{usecTime / 1000000, usecTime % 1000000, size, frameSize};
    Serial.write((uint8_t*)&frameHeader, sizeof(PcapRecordHeader));
    Serial.write(buffer, frameSize);
}

void PcapFile::writeHeader()
{
    PcapGlobalHeader globalHeader{PCAP_MAGIC_NUMBER, 2, 4, 0, 0, SNAPLEN, LINKTYPE_IEEE802_11};
    //Serial.print("\xD4\xC3\xB2\xA1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\x00\x00\x69\x00\x00\x00");
    Serial.write((uint8_t*)&globalHeader, sizeof(PcapGlobalHeader));
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
