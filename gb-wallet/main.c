/* SPDX-License-Identifier: GPLv3 */
/*!
 * @file main.c
 * @brief Game Boy Wallet ROM — main entry point.
 *
 * Custom GB ROM implementing a Bitcoin wallet UI.
 * Communicates with the RP2350 via shared SRAM protocol.
 *
 * ## State Machine
 *
 * SPLASH → HOME ↔ (all sub-screens)
 *
 * - HOME: Main menu (New/Import/Receive/Sign/Export/Settings/Lock)
 * - UNLOCK_PIN: PIN entry to unlock wallet
 * - SET_PIN: Set/change PIN
 * - SEED_VIEW: Display seed words one at a time
 * - ADDRESS_VIEW: Show receive address (scrollable)
 * - TX_CONFIRM: Display transaction for confirmation
 * - SETTINGS: Network toggle, wipe, xpub, back
 * - XPUB_VIEW: Display extended public key (scrollable)
 *
 * ## Controls
 *
 * - D-pad Up/Down: Navigate / change digit
 * - D-pad Left/Right: Previous/next item (seed words, scroll)
 * - A button: Select / confirm
 * - B button: Back / cancel
 * - Start: Return to home
 */

#include <gbdk/platform.h>
#include <gbdk/font.h>
#include <string.h>
#include <stdio.h>

#include "font.h"
#include "sram_comm.h"
#include "ui.h"

/* ---- MBC5 RAM enable (required for SRAM access) ---- */
#define MBC5_RAM_ENABLE ((volatile uint8_t *)0x0000)

static void enable_sram(void)
{
    /* Enable SRAM access for MBC5 */
    *MBC5_RAM_ENABLE = 0x0A;
}

/* ---- BIP-39 word list (subset for display — full 2048 stored as indices) ---- */
/* We send word indices to RP2350 and receive them back.
 * For display, the RP2350 sends back the actual word text.
 * For now we use a minimal set for testing. */

/* ---- Wallet state machine ---- */

typedef enum {
    WS_NO_WALLET,    /* No seed stored */
    WS_LOCKED,       /* Seed stored but locked */
    WS_UNLOCKED,     /* Seed decrypted, ready to use */
} wallet_state_t;

/* ---- Global state ---- */

static ui_context_t ui_ctx;
static uint8_t font_tiles;
static wallet_state_t wallet_state;
static uint8_t redraw;

/* Seed word buffer: 24 words max, each up to 12 chars */
#define MAX_WORDS 24
#define MAX_WORD_LEN 13
static char seed_words[MAX_WORDS][MAX_WORD_LEN];
static uint8_t seed_word_count;

/* ---- Forward declarations ---- */
static void handle_splash_input(void);
static void handle_home_input(void);
static void handle_pin_input(void);
static void handle_seed_view_input(void);
static void handle_address_input(void);
static void handle_settings_input(void);
static void handle_tx_confirm_input(void);
static void handle_xpub_input(void);
static void handle_wipe_confirm_input(void);

/* ---- Helper: wait for any key press ---- */
static uint8_t wait_for_key(void)
{
    uint8_t keys = joypad();
    while (!keys) {
        vsync();
        keys = joypad();
    }
    waitpadup();
    return keys;
}

/* ---- Helper: check if wallet has a seed stored ---- */
static uint8_t check_has_seed(void)
{
    uint8_t rsp;
    rsp = sram_comm_send_command(CMD_EXPORT_SEED, NULL, 0, NULL, 0);
    return rsp != RSP_NO_SEED;
}

/* ---- Helper: request address from RP2350 ---- */
static void request_address(uint8_t *addr_buf, uint16_t buf_size)
{
    uint8_t payload[5];
    payload[0] = 0;  /* index byte 0 */
    payload[1] = 0;
    payload[2] = 0;
    payload[3] = 0;
    payload[4] = 0;  /* addr_type: 0 = native segwit */

    sram_comm_send_command(CMD_GET_ADDRESS, payload, 5,
                           addr_buf, buf_size);
}

/* ---- Main ---- */

void main(void)
{
    /* Enable SRAM */
    enable_sram();

    /* Initialize display */
    font_t sys_font;
    font_init();
    sys_font = font_load(font_ibm);
    font_set(sys_font);
    mode(M_TEXT_OUT | M_NO_SCROLL);

    /* Load our custom font */
    font_tiles = 128; /* Start after system tiles */
    font_load(font_tiles);

    /* Initialize SRAM communication */
    sram_comm_init();

    /* Initialize UI */
    ui_init(&ui_ctx);
    ui_ctx.state = UI_STATE_SPLASH;
    wallet_state = WS_NO_WALLET;
    redraw = 1;

    DISPLAY_ON;

    /* ---- Main loop ---- */
    while (1) {
        vsync();

        if (redraw) {
            ui_draw(&ui_ctx, font_tiles);
            redraw = 0;
        }

        /* Handle input based on current state */
        switch (ui_ctx.state) {
            case UI_STATE_SPLASH:
                handle_splash_input();
                break;
            case UI_STATE_HOME:
                handle_home_input();
                break;
            case UI_STATE_UNLOCK_PIN:
            case UI_STATE_SET_PIN:
                handle_pin_input();
                break;
            case UI_STATE_SEED_VIEW:
                handle_seed_view_input();
                break;
            case UI_STATE_ADDRESS_VIEW:
                handle_address_input();
                break;
            case UI_STATE_TX_CONFIRM:
                handle_tx_confirm_input();
                break;
            case UI_STATE_SETTINGS:
                handle_settings_input();
                break;
            case UI_STATE_XPUB_VIEW:
                handle_xpub_input();
                break;
            case UI_STATE_WIPE_CONFIRM:
                handle_wipe_confirm_input();
                break;
            case UI_STATE_GENERATING:
                /* Animated, no input during generation */
                ui_ctx.anim_counter++;
                redraw = 1;
                break;
            case UI_STATE_SUCCESS:
            case UI_STATE_ERROR:
                wait_for_key();
                ui_ctx.state = UI_STATE_HOME;
                ui_ctx.cursor = 0;
                redraw = 1;
                break;
        }
    }
}

/* ---- Input handlers ---- */

static void handle_splash_input(void)
{
    uint8_t keys = joypad();
    if (!keys) return;
    waitpadup();

    /* Check wallet state to determine where to go */
    if (check_has_seed()) {
        wallet_state = WS_LOCKED;
        ui_ctx.state = UI_STATE_UNLOCK_PIN;
        ui_ctx.pin_pos = 0;
        ui_ctx.pin_length = 0;
        memset(ui_ctx.pin_digits, 0, sizeof(ui_ctx.pin_digits));
    } else {
        wallet_state = WS_NO_WALLET;
        ui_ctx.state = UI_STATE_HOME;
        ui_ctx.cursor = HOME_NEW_WALLET;
    }
    redraw = 1;
}

static void handle_home_input(void)
{
    uint8_t keys = joypad();
    if (!keys) return;
    waitpadup();

    if (keys & J_UP) {
        if (ui_ctx.cursor > 0) ui_ctx.cursor--;
        redraw = 1;
    } else if (keys & J_DOWN) {
        if (ui_ctx.cursor < HOME_ITEM_COUNT - 1) ui_ctx.cursor++;
        redraw = 1;
    } else if (keys & J_A) {
        switch (ui_ctx.cursor) {
            case HOME_NEW_WALLET:
                /* Generate new seed */
                {
                    uint8_t payload[1] = {12}; /* 12 words */
                    uint8_t rsp = sram_comm_send_command(
                        CMD_GENERATE_SEED, payload, 1,
                        NULL, 0);

                    if (rsp == RSP_OK) {
                        /* Now export to get the words */
                        uint8_t word_data[48]; /* 12 * 4 bytes */
                        rsp = sram_comm_send_command(
                            CMD_EXPORT_SEED, NULL, 0,
                            word_data, sizeof(word_data));

                        if (rsp == RSP_OK) {
                            /* For now, show placeholder text.
                             * Full implementation would parse word indices
                             * and look up BIP-39 words. */
                            seed_word_count = 12;
                            for (uint8_t i = 0; i < seed_word_count; i++) {
                                sprintf(seed_words[i], "word_%d", i + 1);
                            }
                            ui_ctx.state = UI_STATE_SEED_VIEW;
                            ui_ctx.cursor = 0;
                            ui_ctx.data_len = seed_word_count;
                            strcpy(ui_ctx.text_buf, seed_words[0]);

                            /* Prompt for PIN */
                            wallet_state = WS_UNLOCKED;
                        } else {
                            strcpy(ui_ctx.text_buf, "Seed gen failed");
                            ui_ctx.state = UI_STATE_ERROR;
                        }
                    } else {
                        strcpy(ui_ctx.text_buf, "Seed gen failed");
                        ui_ctx.state = UI_STATE_ERROR;
                    }
                }
                break;

            case HOME_IMPORT_WALLET:
                /* TODO: Import flow — enter word by word */
                strcpy(ui_ctx.text_buf, "Not implemented");
                ui_ctx.state = UI_STATE_ERROR;
                break;

            case HOME_RECEIVE:
                /* Request address from RP2350 */
                request_address((uint8_t *)ui_ctx.text_buf,
                               sizeof(ui_ctx.text_buf));
                ui_ctx.state = UI_STATE_ADDRESS_VIEW;
                ui_ctx.scroll_offset = 0;
                break;

            case HOME_SIGN_TX:
                /* Notify RP2350 we're ready to sign */
                {
                    uint8_t rsp = sram_comm_send_command(
                        CMD_SIGN_PSBT, NULL, 0, NULL, 0);
                    (void)rsp;
                    /* TX details would come via USB → RP2350 → GB.
                     * For now show placeholder. */
                    strcpy(ui_ctx.text_buf, "Waiting for TX...");
                    ui_ctx.state = UI_STATE_GENERATING;
                }
                break;

            case HOME_EXPORT_SEED:
                if (wallet_state != WS_UNLOCKED) {
                    strcpy(ui_ctx.text_buf, "Unlock first");
                    ui_ctx.state = UI_STATE_ERROR;
                } else {
                    /* Request seed words */
                    uint8_t word_data[48];
                    uint8_t rsp = sram_comm_send_command(
                        CMD_EXPORT_SEED, NULL, 0,
                        word_data, sizeof(word_data));
                    (void)rsp;
                    /* Placeholder */
                    seed_word_count = 12;
                    for (uint8_t i = 0; i < seed_word_count; i++) {
                        sprintf(seed_words[i], "word_%d", i + 1);
                    }
                    ui_ctx.state = UI_STATE_SEED_VIEW;
                    ui_ctx.cursor = 0;
                    ui_ctx.data_len = seed_word_count;
                    strcpy(ui_ctx.text_buf, seed_words[0]);
                }
                break;

            case HOME_SETTINGS:
                ui_ctx.state = UI_STATE_SETTINGS;
                ui_ctx.cursor = 0;
                break;

            case HOME_LOCK:
                sram_comm_send_command(CMD_LOCK, NULL, 0, NULL, 0);
                wallet_state = WS_LOCKED;
                ui_ctx.state = UI_STATE_SPLASH;
                break;
        }
        redraw = 1;
    } else if (keys & J_B) {
        /* Back to splash */
        ui_ctx.state = UI_STATE_SPLASH;
        redraw = 1;
    }
}

static void handle_pin_input(void)
{
    uint8_t keys = joypad();
    if (!keys) return;
    waitpadup();

    if (keys & J_UP) {
        /* Increment current digit */
        ui_ctx.pin_digits[ui_ctx.pin_pos]++;
        if (ui_ctx.pin_digits[ui_ctx.pin_pos] > 9) {
            ui_ctx.pin_digits[ui_ctx.pin_pos] = 0;
        }
        redraw = 1;
    } else if (keys & J_DOWN) {
        /* Decrement current digit */
        if (ui_ctx.pin_digits[ui_ctx.pin_pos] == 0) {
            ui_ctx.pin_digits[ui_ctx.pin_pos] = 9;
        } else {
            ui_ctx.pin_digits[ui_ctx.pin_pos]--;
        }
        redraw = 1;
    } else if (keys & J_RIGHT) {
        /* Move to next digit */
        if (ui_ctx.pin_pos < ui_ctx.max_pin_pos - 1) {
            ui_ctx.pin_pos++;
        }
        redraw = 1;
    } else if (keys & J_LEFT) {
        /* Move to previous digit */
        if (ui_ctx.pin_pos > 0) {
            ui_ctx.pin_pos--;
        }
        redraw = 1;
    } else if (keys & J_A) {
        /* Confirm PIN */
        if (ui_ctx.state == UI_STATE_SET_PIN) {
            /* Set new PIN */
            uint8_t rsp = sram_comm_send_command(
                CMD_SET_PIN, ui_ctx.pin_digits, ui_ctx.max_pin_pos,
                NULL, 0);
            if (rsp == RSP_OK) {
                strcpy(ui_ctx.text_buf, "PIN set!");
                ui_ctx.state = UI_STATE_SUCCESS;
                wallet_state = WS_UNLOCKED;
            } else {
                strcpy(ui_ctx.text_buf, "PIN set failed");
                ui_ctx.state = UI_STATE_ERROR;
            }
        } else {
            /* Unlock with PIN */
            uint8_t rsp = sram_comm_send_command(
                CMD_UNLOCK, ui_ctx.pin_digits, ui_ctx.max_pin_pos,
                NULL, 0);
            if (rsp == RSP_OK) {
                wallet_state = WS_UNLOCKED;
                ui_ctx.state = UI_STATE_HOME;
                ui_ctx.cursor = HOME_RECEIVE;
            } else if (rsp == RSP_WRONG_PIN) {
                strcpy(ui_ctx.text_buf, "Wrong PIN!");
                ui_ctx.state = UI_STATE_ERROR;
            } else {
                strcpy(ui_ctx.text_buf, "Unlock failed");
                ui_ctx.state = UI_STATE_ERROR;
            }
        }
        redraw = 1;
    } else if (keys & J_B) {
        /* Cancel */
        ui_ctx.state = UI_STATE_SPLASH;
        redraw = 1;
    }
}

static void handle_seed_view_input(void)
{
    uint8_t keys = joypad();
    if (!keys) return;
    waitpadup();

    if ((keys & J_RIGHT) || (keys & J_DOWN)) {
        if (ui_ctx.cursor < seed_word_count - 1) {
            ui_ctx.cursor++;
            strcpy(ui_ctx.text_buf, seed_words[ui_ctx.cursor]);
            redraw = 1;
        }
    } else if ((keys & J_LEFT) || (keys & J_UP)) {
        if (ui_ctx.cursor > 0) {
            ui_ctx.cursor--;
            strcpy(ui_ctx.text_buf, seed_words[ui_ctx.cursor]);
            redraw = 1;
        }
    } else if (keys & J_B) {
        ui_ctx.state = UI_STATE_HOME;
        ui_ctx.cursor = HOME_RECEIVE;
        redraw = 1;
    }
}

static void handle_address_input(void)
{
    uint8_t keys = joypad();
    if (!keys) return;
    waitpadup();

    uint16_t addr_len = strlen(ui_ctx.text_buf);

    if (keys & J_DOWN) {
        if (ui_ctx.scroll_offset + 60 < addr_len) {
            ui_ctx.scroll_offset += 20;
            redraw = 1;
        }
    } else if (keys & J_UP) {
        if (ui_ctx.scroll_offset >= 20) {
            ui_ctx.scroll_offset -= 20;
            redraw = 1;
        }
    } else if (keys & J_B) {
        ui_ctx.state = UI_STATE_HOME;
        ui_ctx.cursor = HOME_RECEIVE;
        redraw = 1;
    }
}

static void handle_tx_confirm_input(void)
{
    uint8_t keys = joypad();
    if (!keys) return;
    waitpadup();

    if (keys & J_A) {
        /* Confirm signing */
        uint8_t rsp = sram_comm_send_command(
            CMD_SIGN_PSBT, (uint8_t *)"Y", 1, NULL, 0);
        (void)rsp;
        strcpy(ui_ctx.text_buf, "TX Signed!");
        ui_ctx.state = UI_STATE_SUCCESS;
        redraw = 1;
    } else if (keys & J_B) {
        /* Reject */
        ui_ctx.state = UI_STATE_HOME;
        ui_ctx.cursor = HOME_SIGN_TX;
        redraw = 1;
    }
}

static void handle_settings_input(void)
{
    uint8_t keys = joypad();
    if (!keys) return;
    waitpadup();

    if (keys & J_UP) {
        if (ui_ctx.cursor > 0) ui_ctx.cursor--;
        redraw = 1;
    } else if (keys & J_DOWN) {
        if (ui_ctx.cursor < SETTINGS_ITEM_COUNT - 1) ui_ctx.cursor++;
        redraw = 1;
    } else if (keys & J_A) {
        switch (ui_ctx.cursor) {
            case SETTINGS_NETWORK:
                ui_ctx.network = ui_ctx.network == 0 ? 1 : 0;
                break;
            case SETTINGS_WIPE:
                ui_ctx.state = UI_STATE_WIPE_CONFIRM;
                break;
            case SETTINGS_XPUB:
                /* Request xpub from RP2350 */
                {
                    uint8_t net_payload[1] = {ui_ctx.network};
                    sram_comm_send_command(CMD_GET_XPUB, net_payload, 1,
                                          (uint8_t *)ui_ctx.text_buf,
                                          sizeof(ui_ctx.text_buf));
                    ui_ctx.state = UI_STATE_XPUB_VIEW;
                    ui_ctx.scroll_offset = 0;
                }
                break;
            case SETTINGS_BACK:
                ui_ctx.state = UI_STATE_HOME;
                break;
        }
        redraw = 1;
    } else if (keys & J_B) {
        ui_ctx.state = UI_STATE_HOME;
        ui_ctx.cursor = HOME_SETTINGS;
        redraw = 1;
    }
}

static void handle_xpub_input(void)
{
    uint8_t keys = joypad();
    if (!keys) return;
    waitpadup();

    uint16_t len = strlen(ui_ctx.text_buf);

    if (keys & J_DOWN) {
        if (ui_ctx.scroll_offset + 200 < len) {
            ui_ctx.scroll_offset += 20;
            redraw = 1;
        }
    } else if (keys & J_UP) {
        if (ui_ctx.scroll_offset >= 20) {
            ui_ctx.scroll_offset -= 20;
            redraw = 1;
        }
    } else if (keys & J_B) {
        ui_ctx.state = UI_STATE_SETTINGS;
        ui_ctx.cursor = SETTINGS_XPUB;
        redraw = 1;
    }
}

static void handle_wipe_confirm_input(void)
{
    uint8_t keys = joypad();
    if (!keys) return;
    waitpadup();

    if (keys & J_A) {
        uint8_t confirm = 0xA5;
        uint8_t rsp = sram_comm_send_command(
            CMD_WIPE, &confirm, 1, NULL, 0);
        if (rsp == RSP_OK) {
            wallet_state = WS_NO_WALLET;
            strcpy(ui_ctx.text_buf, "Wallet wiped");
            ui_ctx.state = UI_STATE_SUCCESS;
        } else {
            strcpy(ui_ctx.text_buf, "Wipe failed");
            ui_ctx.state = UI_STATE_ERROR;
        }
        redraw = 1;
    } else if (keys & J_B) {
        ui_ctx.state = UI_STATE_SETTINGS;
        ui_ctx.cursor = SETTINGS_WIPE;
        redraw = 1;
    }
}
