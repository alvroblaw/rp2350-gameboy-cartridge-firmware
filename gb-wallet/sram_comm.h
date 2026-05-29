/* SPDX-License-Identifier: GPLv3 */
/*!
 * @file sram_comm.h
 * @brief SRAM communication between GB wallet ROM and RP2350.
 *
 * Uses shared SRAM regions defined in PROTOCOL.md for bidirectional
 * command/response protocol with CRC-16-CCITT integrity checking.
 *
 * ## SRAM Memory Map
 *
 * | Offset    | Size  | Purpose                    |
 * |-----------|-------|----------------------------|
 * | 0x1F00    | 64 B  | Command region (GB→RP2350) |
 * | 0x1F40    | 64 B  | Response region (RP2350→GB)|
 * | 0x1F80    | 112 B | Extended payload buffer    |
 * | 0x1FF0    | 1 B   | Status byte                |
 */
#ifndef SRAM_COMM_H
#define SRAM_COMM_H

#include <stdint.h>

/* ---- SRAM addresses (offsets from SRAM base at 0xA000) ---- */
#define SCMD_CMD_REGION     0x1F00
#define SCMD_CMD_SIZE       64
#define SCMD_RSP_REGION     0x1F40
#define SCMD_RSP_SIZE       64
#define SCMD_EXT_PAYLOAD    0x1F80
#define SCMD_EXT_SIZE       112
#define SCMD_STATUS_ADDR    0x1FF0

/* ---- Frame format ---- */
#define SCMD_FRAME_MAGIC    0xB7
#define SCMD_HEADER_SIZE    4   /* magic(1) + cmd(1) + len_lo(1) + len_hi(1) */
#define SCMD_CRC_SIZE       2
#define SCMD_MAX_PAYLOAD    (SCMD_CMD_SIZE + SCMD_EXT_SIZE - SCMD_HEADER_SIZE - SCMD_CRC_SIZE)

/* ---- Status byte bits ---- */
#define SCMD_STATUS_CMD_PENDING  0x01
#define SCMD_STATUS_RSP_READY    0x02
#define SCMD_STATUS_ERROR        0x04
#define SCMD_STATUS_BUSY         0x08

/* ---- Command IDs (must match RP2350 gb_channel.rs) ---- */
#define CMD_GENERATE_SEED   0x01
#define CMD_IMPORT_SEED     0x02
#define CMD_GET_XPUB        0x03
#define CMD_GET_ADDRESS     0x04
#define CMD_SIGN_PSBT       0x05
#define CMD_EXPORT_SEED     0x06
#define CMD_WIPE            0x07
#define CMD_LOCK            0x08
#define CMD_UNLOCK          0x09
#define CMD_SET_PIN         0x0A

/* ---- Response codes ---- */
#define RSP_OK              0x00
#define RSP_ERROR           0x01
#define RSP_INVALID_CMD     0x02
#define RSP_WRONG_PIN       0x03
#define RSP_LOCKED          0x04
#define RSP_NO_SEED         0x05
#define RSP_REJECTED        0x06
#define RSP_CHECKSUM_ERR    0x07

/**
 * Initialize the communication channel.
 * Clears all protocol regions and resets the status byte.
 */
void sram_comm_init(void);

/**
 * Send a command with payload to the RP2350.
 * Blocks until response is received.
 *
 * @param cmd     Command ID (CMD_xxx)
 * @param payload Payload data (may be NULL if len==0)
 * @param len     Payload length in bytes
 * @param rsp_buf Buffer to store response payload (may be NULL)
 * @param rsp_buf_size Size of response buffer
 * @return Response code (RSP_xxx), or 0xFF on communication error
 */
uint8_t sram_comm_send_command(uint8_t cmd, const uint8_t *payload,
                               uint16_t len, uint8_t *rsp_buf,
                               uint16_t rsp_buf_size);

/**
 * Wait for a response from the RP2350.
 * Polls the status byte until RSP_READY is set.
 *
 * @param rsp_buf Buffer to store response payload (may be NULL)
 * @param rsp_buf_size Size of response buffer
 * @return Response code byte (RSP_xxx)
 */
uint8_t sram_comm_wait_response(uint8_t *rsp_buf, uint16_t rsp_buf_size);

/**
 * Compute CRC-16-CCITT over data.
 * Polynomial 0x1021, init 0xFFFF.
 */
uint16_t sram_comm_crc16(const uint8_t *data, uint16_t len);

/**
 * Check if a response is ready.
 * Returns non-zero if response available.
 */
uint8_t sram_comm_has_response(void);

/**
 * Clear the response-ready flag (after reading response).
 */
void sram_comm_clear_response(void);

#endif /* SRAM_COMM_H */
