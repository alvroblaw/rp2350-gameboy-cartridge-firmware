/* SPDX-License-Identifier: GPLv3 */
/*!
 * @file sram_comm.c
 * @brief SRAM communication between GB wallet ROM and RP2350.
 *
 * Implements the frame protocol from PROTOCOL.md:
 * [MAGIC:0xB7][CMD:u8][LEN:u16 LE][PAYLOAD:N][CRC16:u16 LE]
 */

#include "sram_comm.h"
#include <string.h>

/* ---- Volatile SRAM access ---- */

/* GB SRAM is mapped at 0xA000-0xBFFF (8 KiB per bank) */
#define SRAM_BASE ((volatile uint8_t *)0xA000)

static inline volatile uint8_t *sram_ptr(uint16_t offset)
{
    return SRAM_BASE + offset;
}

static inline uint8_t sram_read(uint16_t offset)
{
    return *sram_ptr(offset);
}

static inline void sram_write(uint16_t offset, uint8_t val)
{
    *sram_ptr(offset) = val;
}

static void sram_read_buf(uint16_t offset, uint8_t *dst, uint16_t len)
{
    for (uint16_t i = 0; i < len; i++) {
        dst[i] = sram_read(offset + i);
    }
}

static void sram_write_buf(uint16_t offset, const uint8_t *src, uint16_t len)
{
    for (uint16_t i = 0; i < len; i++) {
        sram_write(offset + i, src[i]);
    }
}

static void sram_fill(uint16_t offset, uint8_t val, uint16_t len)
{
    for (uint16_t i = 0; i < len; i++) {
        sram_write(offset + i, val);
    }
}

/* ---- CRC-16-CCITT ---- */

uint16_t sram_comm_crc16(const uint8_t *data, uint16_t len)
{
    uint16_t crc = 0xFFFF;
    for (uint16_t i = 0; i < len; i++) {
        crc ^= ((uint16_t)data[i]) << 8;
        for (uint8_t j = 0; j < 8; j++) {
            if (crc & 0x8000) {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    return crc;
}

/* ---- Status byte management ---- */

static uint8_t read_status(void)
{
    return sram_read(SCMD_STATUS_ADDR);
}

static void write_status(uint8_t val)
{
    sram_write(SCMD_STATUS_ADDR, val);
}

/* ---- Public API ---- */

void sram_comm_init(void)
{
    sram_fill(SCMD_CMD_REGION, 0, SCMD_CMD_SIZE);
    sram_fill(SCMD_RSP_REGION, 0, SCMD_RSP_SIZE);
    sram_fill(SCMD_EXT_PAYLOAD, 0, SCMD_EXT_SIZE);
    write_status(0);
}

uint8_t sram_comm_has_response(void)
{
    return read_status() & SCMD_STATUS_RSP_READY;
}

void sram_comm_clear_response(void)
{
    uint8_t s = read_status();
    write_status(s & ~SCMD_STATUS_RSP_READY);
}

uint8_t sram_comm_wait_response(uint8_t *rsp_buf, uint16_t rsp_buf_size)
{
    /* Wait for response-ready flag */
    while (!(read_status() & SCMD_STATUS_RSP_READY)) {
        vsync();
    }

    /* Read the response frame from response region */
    uint8_t raw[SCMD_RSP_SIZE];
    sram_read_buf(SCMD_RSP_REGION, raw, SCMD_RSP_SIZE);

    /* Validate magic */
    if (raw[0] != SCMD_FRAME_MAGIC) {
        sram_comm_clear_response();
        return 0xFF;
    }

    uint8_t rsp_code = raw[1];
    uint16_t payload_len = raw[2] | ((uint16_t)raw[3] << 8);

    /* Check if payload extends into extended buffer */
    uint16_t header_payload_in_rsp = SCMD_RSP_SIZE - SCMD_HEADER_SIZE;
    if (payload_len > header_payload_in_rsp) {
        /* Part of payload is in extended buffer */
        if (rsp_buf && payload_len <= rsp_buf_size) {
            memcpy(rsp_buf, &raw[SCMD_HEADER_SIZE], header_payload_in_rsp);
            sram_read_buf(SCMD_EXT_PAYLOAD,
                          rsp_buf + header_payload_in_rsp,
                          payload_len - header_payload_in_rsp);
        }
    } else {
        /* Entire payload fits in response region */
        if (rsp_buf && payload_len <= rsp_buf_size) {
            memcpy(rsp_buf, &raw[SCMD_HEADER_SIZE], payload_len);
        }
    }

    /* Verify CRC (header + payload) */
    uint16_t total_for_crc = SCMD_HEADER_SIZE + payload_len;
    uint8_t crc_buf[SCMD_RSP_SIZE + SCMD_EXT_SIZE];
    sram_read_buf(SCMD_RSP_REGION, crc_buf,
                  total_for_crc < SCMD_RSP_SIZE ? total_for_crc : SCMD_RSP_SIZE);
    if (total_for_crc > SCMD_RSP_SIZE) {
        sram_read_buf(SCMD_EXT_PAYLOAD, crc_buf + SCMD_RSP_SIZE,
                      total_for_crc - SCMD_RSP_SIZE);
    }
    uint16_t expected_crc = sram_comm_crc16(crc_buf, total_for_crc);

    /* Read CRC from frame (after header + payload) */
    uint16_t actual_crc;
    if (total_for_crc + SCMD_CRC_SIZE <= SCMD_RSP_SIZE) {
        actual_crc = sram_read(SCMD_RSP_REGION + total_for_crc) |
                     ((uint16_t)sram_read(SCMD_RSP_REGION + total_for_crc + 1) << 8);
    } else {
        uint16_t crc_offset = total_for_crc - SCMD_RSP_SIZE;
        actual_crc = sram_read(SCMD_EXT_PAYLOAD + crc_offset) |
                     ((uint16_t)sram_read(SCMD_EXT_PAYLOAD + crc_offset + 1) << 8);
    }

    sram_comm_clear_response();

    if (expected_crc != actual_crc) {
        return RSP_CHECKSUM_ERR;
    }

    return rsp_code;
}

uint8_t sram_comm_send_command(uint8_t cmd, const uint8_t *payload,
                                uint16_t len, uint8_t *rsp_buf,
                                uint16_t rsp_buf_size)
{
    /* Build frame */
    uint8_t frame[SCMD_CMD_SIZE + SCMD_EXT_SIZE];
    uint16_t frame_size = SCMD_HEADER_SIZE + len + SCMD_CRC_SIZE;

    if (frame_size > sizeof(frame)) {
        return 0xFF;
    }

    /* Header */
    frame[0] = SCMD_FRAME_MAGIC;
    frame[1] = cmd;
    frame[2] = len & 0xFF;
    frame[3] = (len >> 8) & 0xFF;

    /* Payload */
    if (payload && len > 0) {
        memcpy(&frame[SCMD_HEADER_SIZE], payload, len);
    }

    /* CRC over header + payload */
    uint16_t crc = sram_comm_crc16(frame, SCMD_HEADER_SIZE + len);
    frame[SCMD_HEADER_SIZE + len] = crc & 0xFF;
    frame[SCMD_HEADER_SIZE + len + 1] = (crc >> 8) & 0xFF;

    /* Write frame to SRAM command region + extended buffer */
    uint16_t to_cmd = frame_size < SCMD_CMD_SIZE ? frame_size : SCMD_CMD_SIZE;
    sram_write_buf(SCMD_CMD_REGION, frame, to_cmd);

    if (frame_size > SCMD_CMD_SIZE) {
        sram_write_buf(SCMD_EXT_PAYLOAD, frame + SCMD_CMD_SIZE,
                       frame_size - SCMD_CMD_SIZE);
    }

    /* Set command-pending flag */
    write_status(read_status() | SCMD_STATUS_CMD_PENDING);

    /* Wait for response */
    return sram_comm_wait_response(rsp_buf, rsp_buf_size);
}
