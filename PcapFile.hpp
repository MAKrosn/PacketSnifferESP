#pragma once

/**
 * @file PcapFile.hpp
 * @author MAKrosniak (michal@krosniak.it)
 * @date 2023-10-20
 * @copyright Copyright (c) 2023
 *
 * @brief Provides implementation generate PCAP formatted binary from raw frame bytes
 */

#include <stdint.h>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <Stream.h>

/**
 * @brief Constanst according to reference
 *
 * @see Ref: https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat#global-header
 */
constexpr uint32_t SNAPLEN = 65535u;
constexpr uint32_t PCAP_MAGIC_NUMBER = 0b10100001101100101100001111010100u;
constexpr uint32_t LINKTYPE_IEEE802_11 = 105u;
constexpr uint32_t DLT_IEEE802_11_RADIO = 127u;

struct PcapGlobalHeader
{
    uint32_t magic_number = PCAP_MAGIC_NUMBER; /* magic number */
    uint16_t version_major = 2u;                /* major version number */
    uint16_t version_minor = 4u;                /* minor version number */
    int32_t thiszone = 0;                      /* GMT to local correction */
    uint32_t sigfigs = 0u;                      /* accuracy of timestamps */
    uint32_t snaplen = SNAPLEN;                /* max length of captured packets, in octets */
    uint32_t network = DLT_IEEE802_11_RADIO;    /* data link type */
} __attribute__((packed));;

struct PcapRecordHeader
{
    uint32_t ts_sec;   /* timestamp seconds */
    uint32_t ts_usec;  /* timestamp microseconds */
    uint32_t incl_len; /* number of octets of packet saved in file */
    uint32_t orig_len; /* actual length of packet */
} __attribute__((packed));;

struct PcapRecord
{
    PcapRecordHeader pcapRecordHeader;
    std::vector<uint8_t> data; /*record data storage*/
    size_t getSize() { return sizeof(PcapRecordHeader) + data.size(); }
};

struct PcapFile
{
    /**
     * @brief Prepares new empty buffer for PCAP formatted binary data.
     *
     * Has always to be called before
     */
    PcapFile(Stream& stream);
    /**
     * @brief Appends new frame to existing PCAP buffer.
     *
     * Expects pcap_serializer_append_frame() was already called.
     * @param buffer frame buffer that should be appended to PCAP
     * @param size size of frame buffer
     * @param ts_usec timestamp of captured frame in microseconds
     */
    void appendFrame(const uint8_t *buffer, size_t frameSize, uint32_t usecTime);
    /**
     * @brief Returns size of PCAP buffer in bytes (recalculated)
     *
     * @return unsigned
     */
    size_t getBufferSize();

    /**
     * @brief Return pointer to PCAP buffer
     *
     * @return uint8_t*
     */
    bool writeBufferToSerialOutput();

    /**
     * @brief Return pointer to PCAP buffer
     *
     * @return uint8_t*
     */
    void directSerialOutput(const uint8_t *buffer, size_t frameSize, uint32_t usecTime);

    /**
     * @brief Return pointer to PCAP buffer
     *
     * @return uint8_t*
     */
    void writeHeader();

private:
    std::vector<PcapRecord> recordsBuffer; /* stored frames */
    size_t size;                           /* stored size variable*/
    Stream& Serial;
};