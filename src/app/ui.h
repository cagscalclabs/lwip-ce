#ifndef LWIP_APP_UI_H
#define LWIP_APP_UI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum
{
    UI_BG = 1,
    UI_SURFACE,
    UI_TEXT,
    UI_MUTED,
    UI_ACCENT,
    UI_SELECT,
    UI_LINE,
    UI_HEADER,
    UI_HEADER_TEXT,
    UI_GOOD,
    UI_BAD,
    UI_WARN,
    UI_SHADOW
};

#define UI_WIDTH 320
#define UI_HEIGHT 240
#define UI_HEADER_H 24
#define UI_STATUS_H 16
#define UI_FOOTER_H 18
#define UI_ROW_H 26

#define UI_KEY_REDRAW 0xFF

typedef enum
{
    UI_ITEM_SECTION,
    UI_ITEM_ACTION,
    UI_ITEM_VALUE,
    UI_ITEM_TOGGLE,
    UI_ITEM_LINE
} ui_item_kind_t;

typedef struct
{
    ui_item_kind_t kind;
    const char *label;
    const char *hint;
    const char *value;
    bool on;
    uint8_t value_color;
} ui_item_t;

typedef struct
{
    int selected;
    int scroll;
} ui_list_t;

typedef bool (*ui_idle_fn)(void);

void ui_begin(void);
void ui_end(void);
void ui_set_idle(ui_idle_fn idle);
uint8_t ui_wait_key(void);

void ui_frame(const char *title, const char *right, const char *status, uint8_t status_color,
              const char *keys);
void ui_list_draw(ui_list_t *list, const ui_item_t *items, int count);
bool ui_list_key(ui_list_t *list, const ui_item_t *items, int count, uint8_t key);
void ui_body_text(const char *const *lines, int count, int scroll);
int ui_body_rows(void);
void ui_present(void);

bool ui_edit_text(const char *title, char *buffer, size_t size, bool secret);
int ui_choose(const char *title, const char *const *items, int count, int selected);
bool ui_confirm(const char *title, const char *question);
void ui_message(const char *title, const char *line1, const char *line2);
void ui_busy(const char *title, const char *text);

#endif
