/* SPDX-License-Identifier: GPLv3 */
/*!
 * @file font.h
 * @brief Compact bitmap font for Game Boy wallet ROM.
 *
 * 5x8 pixel monospaced font covering ASCII 32-126.
 * Each character is stored as 5 bytes (one byte per row, 5 bits used).
 * Rendered as GB background tiles (8x8, top 5 columns used).
 */
#ifndef FONT_H
#define FONT_H

#include <stdint.h>

/* First printable character in our font table */
#define FONT_FIRST_CHAR 32
/* Last printable character */
#define FONT_LAST_CHAR  126
/* Number of characters in the font */
#define FONT_CHAR_COUNT (FONT_LAST_CHAR - FONT_FIRST_CHAR + 1)
/* Character width in pixels */
#define FONT_WIDTH  5
/* Character height in pixels */
#define FONT_HEIGHT 8
/* Bytes per character glyph (one byte per row) */
#define FONT_BYTES_PER_CHAR FONT_HEIGHT

/**
 * Font glyph data. Indexed by (char - FONT_FIRST_CHAR).
 * Each entry is FONT_BYTES_PER_CHAR bytes, each byte holds one row
 * of 5 pixels in the low bits (bit 4 = leftmost pixel).
 */
extern const uint8_t font_glyphs[FONT_CHAR_COUNT][FONT_BYTES_PER_CHAR];

/**
 * Load font tiles into VRAM starting at tile index `base_tile`.
 * Returns the number of tiles loaded (FONT_CHAR_COUNT).
 */
uint8_t wallet_font_load(uint8_t base_tile);

/**
 * Get the tile index for a character.
 * Returns 0 for characters outside the printable range.
 */
uint8_t wallet_font_char_tile(char c, uint8_t base_tile);

/**
 * Print a string to the background tilemap at (x, y) tile coordinates.
 * Uses tiles starting at `base_tile` (must have been loaded first).
 * Max 20 chars per line on GB screen.
 */
void wallet_font_print(uint8_t x, uint8_t y, const char *str, uint8_t base_tile);

/**
 * Print a string centered on the given row.
 */
void wallet_font_print_centered(uint8_t y, const char *str, uint8_t base_tile);

/**
 * Print a string right-aligned at column x.
 */
void wallet_font_print_right(uint8_t x, uint8_t y, const char *str, uint8_t base_tile);

/**
 * Clear a row of tiles (fill with space tile).
 */
void wallet_font_clear_row(uint8_t y, uint8_t base_tile);

#endif /* FONT_H */
