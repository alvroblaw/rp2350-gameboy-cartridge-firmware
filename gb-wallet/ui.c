/* SPDX-License-Identifier: GPLv3 */
/*!
 * @file ui.c
 * @brief Wallet UI rendering for Game Boy screen.
 */

#include "ui.h"
#include "font.h"
#include <gbdk/font.h>
#include <gbdk/platform.h>
#include <string.h>
#include <stdio.h>

/* ---- Helpers ---- */

static void clear_screen(uint8_t ft)
{
    for (uint8_t y = 0; y < 18; y++) {
        font_clear_row(y, ft);
    }
}

static void draw_hline(uint8_t y, uint8_t ft)
{
    uint8_t dash = font_char_tile('-', ft);
    for (uint8_t x = 0; x < 20; x++) {
        set_bkg_tile_xy(x, y, dash);
    }
}

static void draw_title(const char *title, uint8_t ft)
{
    font_print_centered(0, title, ft);
    draw_hline(1, ft);
}

/* Reverse highlight for cursor: swap colors on that row */
static void highlight_row(uint8_t y)
{
    /* On DMG we use a different background palette for the highlighted row.
     * On CGB we'd use attribute flags. For simplicity, use '>' marker. */
}

/* ---- Public functions ---- */

void ui_init(ui_context_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = UI_STATE_SPLASH;
    ctx->max_pin_pos = 4; /* default PIN length */
    ctx->network = 0;     /* mainnet */
}

void ui_draw_splash(uint8_t ft)
{
    clear_screen(ft);
    draw_title("= BTC WALLET =", ft);
    font_print_centered(6, "Stealth Wallet", ft);
    font_print_centered(8, "for Game Boy", ft);
    font_print_centered(11, "v0.1.0", ft);
    font_print_centered(16, "Press any key", ft);
}

void ui_draw_home(const ui_context_t *ctx, uint8_t ft)
{
    static const char *items[HOME_ITEM_COUNT] = {
        "New Wallet",
        "Import Wallet",
        "Receive",
        "Sign Transaction",
        "Export Seed",
        "Settings",
        "Lock Wallet",
    };

    clear_screen(ft);
    draw_title("= BTC WALLET =", ft);

    for (uint8_t i = 0; i < HOME_ITEM_COUNT; i++) {
        uint8_t y = 3 + i;
        if (i == ctx->cursor) {
            font_print(1, y, ">", ft);
            font_print(3, y, items[i], ft);
        } else {
            font_print(3, y, items[i], ft);
        }
    }

    /* Network indicator */
    font_print_right(19, 17,
                     ctx->network == 0 ? "MAIN" : "TEST", ft);
}

void ui_draw_pin_entry(const ui_context_t *ctx, uint8_t ft, const char *title)
{
    clear_screen(ft);
    draw_title(title, ft);

    font_print_centered(6, "Enter PIN:", ft);

    /* Draw digit boxes */
    uint8_t start_x = 10 - ctx->max_pin_pos;
    for (uint8_t i = 0; i < ctx->max_pin_pos; i++) {
        uint8_t x = start_x + i * 2;
        if (i < ctx->pin_length) {
            /* Filled digit: show as asterisk */
            char buf[2] = {'*', '\0'};
            font_print(x, 9, buf, ft);
        } else if (i == ctx->pin_pos) {
            /* Current position: show cursor */
            font_print(x, 9, "_", ft);
        } else {
            /* Empty position */
            font_print(x, 9, "-", ft);
        }
    }

    /* Digit value at current position */
    char digit_str[2] = {'0' + ctx->pin_digits[ctx->pin_pos], '\0'};
    font_print_centered(12, digit_str, ft);

    font_print_centered(14, "U/D:digit R:next", ft);
    font_print_centered(15, "A:confirm B:back", ft);
}

void ui_draw_seed_view(const ui_context_t *ctx, uint8_t font_tiles,
                       const char *word_text)
{
    clear_screen(font_tiles);
    draw_title("= SEED WORDS =", font_tiles);

    /* Show "Word N/12" */
    char header[20];
    sprintf(header, "Word %d/%d:", ctx->cursor + 1, ctx->data_len);
    font_print_centered(5, header, font_tiles);

    /* Show the word (large, centered) */
    if (word_text) {
        font_print_centered(8, word_text, font_tiles);
    }

    font_print_centered(14, "< prev  next >", font_tiles);
    font_print_centered(16, "B: done", font_tiles);
}

void ui_draw_address(const ui_context_t *ctx, uint8_t ft)
{
    clear_screen(ft);
    draw_title("= RECEIVE =", ft);

    /* Show address in chunks (20 chars per line) */
    const char *addr = ctx->text_buf;
    uint8_t offset = ctx->scroll_offset;
    uint8_t y = 3;

    for (uint8_t line = 0; line < 4 && offset < strlen(addr); line++) {
        char chunk[21];
        uint8_t remaining = strlen(addr) - offset;
        uint8_t len = remaining < 20 ? remaining : 20;
        memcpy(chunk, addr + offset, len);
        chunk[len] = '\0';
        font_print(0, y + line, chunk, ft);
        offset += 20;
    }

    /* Scroll indicators */
    if (ctx->scroll_offset > 0) {
        font_print(19, 3, "^", ft);
    }
    if (offset < strlen(addr)) {
        font_print(19, 6, "v", ft);
    }

    font_print_centered(14, "U/D: scroll", ft);
    font_print_centered(16, "B: back", ft);
}

void ui_draw_tx_confirm(const ui_context_t *ctx, uint8_t ft)
{
    clear_screen(ft);
    draw_title("= CONFIRM TX =", ft);

    font_print(0, 3, "Send:", ft);
    /* Show amount (from data_buf, assumed formatted in text_buf) */
    font_print(0, 4, ctx->text_buf, ft);

    font_print(0, 6, "To:", ft);
    /* Show truncated destination address */
    char addr_short[17];
    uint16_t addr_len = strlen(ctx->text_buf + 20);
    if (addr_len > 16) {
        memcpy(addr_short, ctx->text_buf + 20, 6);
        addr_short[6] = '.';
        addr_short[7] = '.';
        addr_short[8] = '.';
        memcpy(addr_short + 9, ctx->text_buf + 20 + addr_len - 7, 7);
        addr_short[16] = '\0';
    } else {
        memcpy(addr_short, ctx->text_buf + 20, addr_len);
        addr_short[addr_len] = '\0';
    }
    font_print(0, 7, addr_short, ft);

    font_print(0, 10, "Fee:", ft);
    font_print(5, 10, ctx->text_buf + 40, ft);

    font_print_centered(14, "A: SIGN  B: REJECT", ft);
    font_print_centered(16, "Start: details", ft);
}

void ui_draw_settings(const ui_context_t *ctx, uint8_t ft)
{
    clear_screen(ft);
    draw_title("= SETTINGS =", ft);

    font_print(3, 3, "Network:", ft);
    font_print(13, 3, ctx->network == 0 ? "Mainnet" : "Testnet", ft);

    font_print(3, 5, "Wipe Wallet", ft);
    font_print(3, 7, "Show xpub", ft);
    font_print(3, 9, "Back", ft);

    /* Cursor */
    uint8_t cursor_y = 0;
    switch (ctx->cursor) {
        case SETTINGS_NETWORK: cursor_y = 3; break;
        case SETTINGS_WIPE:    cursor_y = 5; break;
        case SETTINGS_XPUB:    cursor_y = 7; break;
        case SETTINGS_BACK:    cursor_y = 9; break;
    }
    font_print(1, cursor_y, ">", ft);
}

void ui_draw_xpub(const ui_context_t *ctx, uint8_t ft)
{
    clear_screen(ft);
    draw_title("= XPUB =", ft);

    const char *xpub = ctx->text_buf;
    uint8_t offset = ctx->scroll_offset;
    uint8_t y = 2;

    for (uint8_t line = 0; line < 12 && offset < strlen(xpub); line++) {
        char chunk[21];
        uint8_t remaining = strlen(xpub) - offset;
        uint8_t len = remaining < 20 ? remaining : 20;
        memcpy(chunk, xpub + offset, len);
        chunk[len] = '\0';
        font_print(0, y + line, chunk, ft);
        offset += 20;
    }

    font_print_centered(16, "U/D:scroll B:back", ft);
}

void ui_draw_success(const char *msg, uint8_t ft)
{
    clear_screen(ft);
    draw_title("= SUCCESS =", ft);
    font_print_centered(8, msg ? msg : "Done!", ft);
    font_print_centered(14, "Press any key", ft);
}

void ui_draw_error(const char *msg, uint8_t ft)
{
    clear_screen(ft);
    draw_title("= ERROR =", ft);
    font_print_centered(8, msg ? msg : "Unknown error", ft);
    font_print_centered(14, "Press any key", ft);
}

void ui_draw_loading(const char *msg, uint8_t ft, uint8_t anim_frame)
{
    clear_screen(ft);
    draw_title("= LOADING =", ft);
    font_print_centered(8, msg ? msg : "Please wait...", ft);

    /* Simple spinner */
    const char *spinner[] = {"|", "/", "-", "\\"};
    font_print_centered(10, spinner[anim_frame & 3], ft);
}

void ui_draw(const ui_context_t *ctx, uint8_t font_tiles)
{
    switch (ctx->state) {
        case UI_STATE_SPLASH:
            ui_draw_splash(font_tiles);
            break;
        case UI_STATE_HOME:
            ui_draw_home(ctx, font_tiles);
            break;
        case UI_STATE_UNLOCK_PIN:
            ui_draw_pin_entry(ctx, font_tiles, "Unlock Wallet");
            break;
        case UI_STATE_SET_PIN:
            ui_draw_pin_entry(ctx, font_tiles, "Set PIN");
            break;
        case UI_STATE_SEED_VIEW:
            ui_draw_seed_view(ctx, font_tiles, ctx->text_buf);
            break;
        case UI_STATE_ADDRESS_VIEW:
            ui_draw_address(ctx, font_tiles);
            break;
        case UI_STATE_TX_CONFIRM:
            ui_draw_tx_confirm(ctx, font_tiles);
            break;
        case UI_STATE_SETTINGS:
            ui_draw_settings(ctx, font_tiles);
            break;
        case UI_STATE_XPUB_VIEW:
            ui_draw_xpub(ctx, font_tiles);
            break;
        case UI_STATE_GENERATING:
            ui_draw_loading("Generating...", font_tiles, ctx->anim_counter);
            break;
        case UI_STATE_WIPE_CONFIRM:
            clear_screen(font_tiles);
            draw_title("= WIPE WALLET =", font_tiles);
            font_print_centered(6, "This will erase", font_tiles);
            font_print_centered(7, "all wallet data!", font_tiles);
            font_print_centered(10, "A: confirm", font_tiles);
            font_print_centered(11, "B: cancel", font_tiles);
            break;
        case UI_STATE_SUCCESS:
            ui_draw_success(ctx->text_buf, font_tiles);
            break;
        case UI_STATE_ERROR:
            ui_draw_error(ctx->text_buf, font_tiles);
            break;
    }
}
