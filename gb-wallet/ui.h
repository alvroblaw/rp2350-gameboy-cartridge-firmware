/* SPDX-License-Identifier: GPLv3 */
/*!
 * @file ui.h
 * @brief Wallet UI rendering for Game Boy screen.
 *
 * Provides screen layouts for the wallet state machine.
 * All rendering uses the custom 5x7 font loaded from font.c.
 *
 * Screen layout: 20 columns x 18 rows of tiles (160x144 px).
 */
#ifndef UI_H
#define UI_H

#include <stdint.h>

/* ---- UI States (match wallet state machine) ---- */
typedef enum {
    UI_STATE_SPLASH,
    UI_STATE_HOME,
    UI_STATE_UNLOCK_PIN,
    UI_STATE_SET_PIN,
    UI_STATE_SEED_VIEW,
    UI_STATE_ADDRESS_VIEW,
    UI_STATE_TX_CONFIRM,
    UI_STATE_SETTINGS,
    UI_STATE_XPUB_VIEW,
    UI_STATE_GENERATING,
    UI_STATE_WIPE_CONFIRM,
    UI_STATE_SUCCESS,
    UI_STATE_ERROR,
} ui_state_t;

/* ---- Home menu items ---- */
typedef enum {
    HOME_NEW_WALLET    = 0,
    HOME_IMPORT_WALLET = 1,
    HOME_RECEIVE       = 2,
    HOME_SIGN_TX       = 3,
    HOME_EXPORT_SEED   = 4,
    HOME_SETTINGS      = 5,
    HOME_LOCK          = 6,
    HOME_ITEM_COUNT
} home_item_t;

/* ---- Settings menu items ---- */
typedef enum {
    SETTINGS_NETWORK  = 0,
    SETTINGS_WIPE     = 1,
    SETTINGS_XPUB     = 2,
    SETTINGS_BACK     = 3,
    SETTINGS_ITEM_COUNT
} settings_item_t;

/* ---- Shared UI state ---- */
typedef struct {
    ui_state_t state;
    uint8_t cursor;          /* General cursor (menu item, seed word index, etc.) */
    uint8_t scroll_offset;   /* For long text scrolling */
    uint8_t pin_digits[8];   /* Current PIN entry buffer */
    uint8_t pin_length;      /* Number of PIN digits entered */
    uint8_t pin_pos;         /* Current digit position being edited */
    uint8_t max_pin_pos;     /* Max digit position */
    uint16_t anim_counter;   /* Animation / timeout counter */

    /* Data buffers for display */
    char text_buf[40];       /* General text buffer (address, xpub, etc.) */
    uint8_t data_buf[128];   /* Raw data from RP2350 responses */
    uint16_t data_len;

    /* Settings */
    uint8_t network;         /* 0 = mainnet, 1 = testnet */
} ui_context_t;

/**
 * Initialize the UI context.
 */
void ui_init(ui_context_t *ctx);

/**
 * Draw the current UI state to the screen.
 * Called once per frame after processing input.
 */
void ui_draw(const ui_context_t *ctx, uint8_t font_tiles);

/**
 * Draw splash screen ("BTC WALLET" + version).
 */
void ui_draw_splash(uint8_t font_tiles);

/**
 * Draw home menu with cursor highlight.
 */
void ui_draw_home(const ui_context_t *ctx, uint8_t font_tiles);

/**
 * Draw PIN entry screen.
 * Shows dots for entered digits, highlight on current digit.
 */
void ui_draw_pin_entry(const ui_context_t *ctx, uint8_t font_tiles, const char *title);

/**
 * Draw seed word display.
 * Shows "Word N/12: <word>" with scroll indicators.
 */
void ui_draw_seed_view(const ui_context_t *ctx, uint8_t font_tiles,
                       const char *word_text);

/**
 * Draw address display (scrollable).
 * Shows address with optional QR code placeholder.
 */
void ui_draw_address(const ui_context_t *ctx, uint8_t font_tiles);

/**
 * Draw TX confirmation screen.
 * Shows destination address (truncated), amount, fee.
 * A=Confirm, B=Reject indicators at bottom.
 */
void ui_draw_tx_confirm(const ui_context_t *ctx, uint8_t font_tiles);

/**
 * Draw settings menu.
 */
void ui_draw_settings(const ui_context_t *ctx, uint8_t font_tiles);

/**
 * Draw xpub display (scrollable, very long).
 */
void ui_draw_xpub(const ui_context_t *ctx, uint8_t font_tiles);

/**
 * Draw a success message with optional detail.
 */
void ui_draw_success(const char *msg, uint8_t font_tiles);

/**
 * Draw an error message.
 */
void ui_draw_error(const char *msg, uint8_t font_tiles);

/**
 * Draw a "generating..." or "loading..." spinner.
 */
void ui_draw_loading(const char *msg, uint8_t font_tiles, uint8_t anim_frame);

#endif /* UI_H */
