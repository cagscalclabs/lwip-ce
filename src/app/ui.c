#include <stdio.h>
#include <string.h>

#include <graphx.h>
#include <ti/getcsc.h>

#include "../tls/includes/bytes.h"
#include "app/ui.h"

#define MARGIN 8
#define DIALOG_W 264

static ui_idle_fn g_idle;
static int g_body_top = UI_HEADER_H;

void ui_begin(void)
{
    gfx_Begin();
    gfx_palette[UI_BG] = gfx_RGBTo1555(238, 241, 246);
    gfx_palette[UI_SURFACE] = gfx_RGBTo1555(255, 255, 255);
    gfx_palette[UI_TEXT] = gfx_RGBTo1555(24, 32, 48);
    gfx_palette[UI_MUTED] = gfx_RGBTo1555(112, 120, 136);
    gfx_palette[UI_ACCENT] = gfx_RGBTo1555(32, 112, 232);
    gfx_palette[UI_SELECT] = gfx_RGBTo1555(214, 230, 255);
    gfx_palette[UI_LINE] = gfx_RGBTo1555(208, 214, 224);
    gfx_palette[UI_HEADER] = gfx_RGBTo1555(20, 34, 64);
    gfx_palette[UI_HEADER_TEXT] = gfx_RGBTo1555(240, 244, 250);
    gfx_palette[UI_GOOD] = gfx_RGBTo1555(40, 160, 80);
    gfx_palette[UI_BAD] = gfx_RGBTo1555(208, 56, 48);
    gfx_palette[UI_WARN] = gfx_RGBTo1555(224, 144, 24);
    gfx_palette[UI_SHADOW] = gfx_RGBTo1555(150, 158, 172);
    gfx_SetTextTransparentColor(0);
    gfx_SetTextBGColor(0);
    gfx_SetDrawBuffer();
}

void ui_end(void)
{
    gfx_End();
}

void ui_set_idle(ui_idle_fn idle)
{
    g_idle = idle;
}

uint8_t ui_wait_key(void)
{
    uint8_t key;

    while ((key = os_GetCSC()) == 0)
    {
        if (g_idle && g_idle())
            return UI_KEY_REDRAW;
    }
    return key;
}

static void text(const char *s, int x, int y, uint8_t color)
{
    gfx_SetTextFGColor(color);
    gfx_PrintStringXY(s, x, y);
}

static void fit(char *out, size_t size, const char *s, int max_width)
{
    size_t len;

    snprintf(out, size, "%s", s ? s : "");
    if ((int)gfx_GetStringWidth(out) <= max_width)
        return;
    len = strlen(out);
    while (len > 2)
    {
        out[len - 1] = '\0';
        out[len - 2] = '.';
        out[len - 3 > 0 ? len - 3 : 0] = '.';
        if ((int)gfx_GetStringWidth(out) <= max_width)
            return;
        len--;
    }
}

static void text_fit(const char *s, int x, int y, int max_width, uint8_t color)
{
    char buf[48];

    fit(buf, sizeof buf, s, max_width);
    text(buf, x, y, color);
}

static void text_right(const char *s, int right, int y, int max_width, uint8_t color)
{
    char buf[48];

    if (!s || !s[0])
        return;
    fit(buf, sizeof buf, s, max_width);
    text(buf, right - (int)gfx_GetStringWidth(buf), y, color);
}

static void text_center(const char *s, int cx, int y, int max_width, uint8_t color)
{
    char buf[56];

    fit(buf, sizeof buf, s, max_width);
    text(buf, cx - (int)gfx_GetStringWidth(buf) / 2, y, color);
}

static void fill(int x, int y, int w, int h, uint8_t color)
{
    gfx_SetColor(color);
    gfx_FillRectangle(x, y, w, h);
}

void ui_frame(const char *title, const char *right, const char *status, uint8_t status_color,
              const char *keys)
{
    gfx_SetClipRegion(0, 0, UI_WIDTH, UI_HEIGHT);
    gfx_FillScreen(UI_BG);

    fill(0, 0, UI_WIDTH, UI_HEADER_H, UI_HEADER);
    fill(0, UI_HEADER_H - 2, UI_WIDTH, 2, UI_ACCENT);
    text_fit(title, MARGIN, 8, 190, UI_HEADER_TEXT);
    text_right(right, UI_WIDTH - MARGIN, 8, 110, UI_SHADOW);

    g_body_top = UI_HEADER_H;
    if (status)
    {
        fill(0, UI_HEADER_H, UI_WIDTH, UI_STATUS_H, UI_SURFACE);
        fill(0, UI_HEADER_H + UI_STATUS_H - 1, UI_WIDTH, 1, UI_LINE);
        gfx_SetColor(status_color);
        gfx_FillCircle(MARGIN + 3, UI_HEADER_H + 7, 3);
        text_fit(status, MARGIN + 12, UI_HEADER_H + 4, UI_WIDTH - 2 * MARGIN - 12, UI_TEXT);
        g_body_top += UI_STATUS_H;
    }

    fill(0, UI_HEIGHT - UI_FOOTER_H, UI_WIDTH, UI_FOOTER_H, UI_SURFACE);
    fill(0, UI_HEIGHT - UI_FOOTER_H, UI_WIDTH, 1, UI_LINE);
    if (keys)
        text_center(keys, UI_WIDTH / 2, UI_HEIGHT - UI_FOOTER_H + 6, UI_WIDTH - 2 * MARGIN, UI_MUTED);
}

int ui_body_rows(void)
{
    return (UI_HEIGHT - UI_FOOTER_H - g_body_top - 2) / UI_ROW_H;
}

static bool selectable(const ui_item_t *item)
{
    return item->kind != UI_ITEM_SECTION && item->kind != UI_ITEM_LINE;
}

static void fix_selection(ui_list_t *list, const ui_item_t *items, int count)
{
    int rows = ui_body_rows();

    if (count <= 0)
    {
        list->selected = 0;
        list->scroll = 0;
        return;
    }
    if (list->selected >= count)
        list->selected = count - 1;
    if (list->selected < 0)
        list->selected = 0;
    while (list->selected < count - 1 && !selectable(&items[list->selected]))
        list->selected++;
    while (list->selected > 0 && !selectable(&items[list->selected]))
        list->selected--;

    if (list->selected < list->scroll)
        list->scroll = list->selected;
    if (list->selected > 0 && list->selected - 1 < list->scroll &&
        items[list->selected - 1].kind == UI_ITEM_SECTION)
        list->scroll = list->selected - 1;
    if (list->selected >= list->scroll + rows)
        list->scroll = list->selected - rows + 1;
    if (list->scroll > count - rows)
        list->scroll = count - rows;
    if (list->scroll < 0)
        list->scroll = 0;
}

static void draw_item(const ui_item_t *item, int y, bool selected)
{
    int right = UI_WIDTH - MARGIN - 10;

    if (item->kind == UI_ITEM_SECTION)
    {
        int w = (int)gfx_GetStringWidth(item->label);

        text(item->label, MARGIN + 2, y + 13, UI_ACCENT);
        fill(MARGIN + 8 + w, y + 16, UI_WIDTH - 3 * MARGIN - 8 - w, 1, UI_LINE);
        return;
    }
    if (item->kind == UI_ITEM_LINE)
    {
        text_fit(item->label, MARGIN + 2, y + 9, UI_WIDTH - 2 * MARGIN - 8, item->value_color ? item->value_color : UI_TEXT);
        return;
    }

    fill(MARGIN - 4, y + 1, UI_WIDTH - 2 * MARGIN, UI_ROW_H - 2, selected ? UI_SELECT : UI_SURFACE);
    if (selected)
        fill(MARGIN - 4, y + 1, 3, UI_ROW_H - 2, UI_ACCENT);

    if (item->kind == UI_ITEM_ACTION)
    {
        text(">", right, y + 9, selected ? UI_ACCENT : UI_MUTED);
        right -= 12;
    }
    if (item->kind == UI_ITEM_TOGGLE)
    {
        fill(right - 22, y + 8, 24, 10, item->on ? UI_ACCENT : UI_LINE);
        fill(item->on ? right - 8 : right - 20, y + 10, 8, 6, UI_SURFACE);
        right -= 32;
    }
    if (item->value && item->value[0])
        text_right(item->value, right, y + 9, 120, item->value_color ? item->value_color : UI_TEXT);

    if (item->hint && item->hint[0])
    {
        text_fit(item->label, MARGIN + 4, y + 4, 180, UI_TEXT);
        text_fit(item->hint, MARGIN + 4, y + 15, 200, UI_MUTED);
    }
    else
    {
        text_fit(item->label, MARGIN + 4, y + 9, 180, UI_TEXT);
    }
}

void ui_list_draw(ui_list_t *list, const ui_item_t *items, int count)
{
    int rows = ui_body_rows();
    int bottom = UI_HEIGHT - UI_FOOTER_H;

    fix_selection(list, items, count);
    gfx_SetClipRegion(0, g_body_top, UI_WIDTH, bottom);
    for (int i = 0; i < rows && list->scroll + i < count; i++)
    {
        int index = list->scroll + i;
        draw_item(&items[index], g_body_top + 2 + i * UI_ROW_H, index == list->selected);
    }
    if (count > rows)
    {
        int height = bottom - g_body_top - 4;
        int thumb = height * rows / count;
        if (thumb < 8)
            thumb = 8;
        fill(UI_WIDTH - 4, g_body_top + 2, 2, height, UI_LINE);
        fill(UI_WIDTH - 4, g_body_top + 2 + (height - thumb) * list->scroll / (count - rows), 2, thumb,
             UI_MUTED);
    }
    gfx_SetClipRegion(0, 0, UI_WIDTH, UI_HEIGHT);
}

bool ui_list_key(ui_list_t *list, const ui_item_t *items, int count, uint8_t key)
{
    int step = key == sk_Up ? -1 : key == sk_Down ? 1 : 0;
    int next = list->selected;

    if (!step)
        return false;
    do
        next += step;
    while (next >= 0 && next < count && !selectable(&items[next]));
    if (next < 0 || next >= count)
    {
        if (step < 0)
            list->scroll = 0;
        return false;
    }
    list->selected = next;
    return true;
}

void ui_body_text(const char *const *lines, int count, int scroll)
{
    int bottom = UI_HEIGHT - UI_FOOTER_H;
    int rows = (bottom - g_body_top - 4) / 12;

    gfx_SetClipRegion(0, g_body_top, UI_WIDTH, bottom);
    for (int i = 0; i < rows && scroll + i < count; i++)
        text_fit(lines[scroll + i], MARGIN, g_body_top + 4 + i * 12, UI_WIDTH - 2 * MARGIN, UI_TEXT);
    gfx_SetClipRegion(0, 0, UI_WIDTH, UI_HEIGHT);
}

void ui_present(void)
{
    gfx_SwapDraw();
}

static int dialog_open(const char *title, int h)
{
    int x = (UI_WIDTH - DIALOG_W) / 2;
    int y = (UI_HEIGHT - h) / 2;

    gfx_BlitScreen();
    fill(x + 3, y + 3, DIALOG_W, h, UI_SHADOW);
    fill(x, y, DIALOG_W, h, UI_SURFACE);
    gfx_SetColor(UI_HEADER);
    gfx_Rectangle(x, y, DIALOG_W, h);
    fill(x, y, DIALOG_W, 18, UI_HEADER);
    text_center(title, UI_WIDTH / 2, y + 5, DIALOG_W - 16, UI_HEADER_TEXT);
    return y;
}

static void dialog_keys(int y, int h, const char *keys)
{
    fill((UI_WIDTH - DIALOG_W) / 2 + 1, y + h - 16, DIALOG_W - 2, 15, UI_BG);
    text_center(keys, UI_WIDTH / 2, y + h - 12, DIALOG_W - 16, UI_MUTED);
}

enum
{
    INPUT_LOWER,
    INPUT_UPPER,
    INPUT_DIGIT,
    INPUT_SYMBOL,
    INPUT_MODES
};

static const char *const input_mode_names[INPUT_MODES] = {"abc", "ABC", "123", "#&!"};

static char key_to_char(uint8_t key, int mode)
{
    static const char letters[64] = {
        0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   'w', 'r', 'm', 'h', 0,
        0,   0,   0,   'v', 'q', 'l', 'g', 0,
        0,   0,   'z', 'u', 'p', 'k', 'f', 'c',
        0,   ' ', 'y', 't', 'o', 'j', 'e', 'b',
        0,   0,   'x', 's', 'n', 'i', 'd', 'a',
        0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0
    };
    static const struct
    {
        uint8_t key;
        char digit;
        char symbol;
    } others[] = {
        {sk_0, '0', ')'}, {sk_1, '1', '!'}, {sk_2, '2', '@'}, {sk_3, '3', '#'},
        {sk_4, '4', '$'}, {sk_5, '5', '%'}, {sk_6, '6', '^'}, {sk_7, '7', '&'},
        {sk_8, '8', '*'}, {sk_9, '9', '('}, {sk_DecPnt, '.', '.'}, {sk_Chs, '-', '~'},
        {sk_Add, '+', '+'}, {sk_Sub, '-', '-'}, {sk_Mul, '*', '_'}, {sk_Div, '/', '/'},
        {sk_Comma, ',', ','}, {sk_LParen, '(', '['}, {sk_RParen, ')', ']'},
        {sk_Power, '^', '='}, {sk_Square, 0, '?'}, {sk_Store, 0, ';'}, {sk_Log, 0, ':'},
        {sk_Ln, 0, '\''}, {sk_Sin, 0, '"'}, {sk_Cos, 0, '<'}, {sk_Tan, 0, '>'},
        {sk_Recip, 0, '\\'}, {sk_GraphVar, 0, '|'},
    };

    if (mode == INPUT_DIGIT || mode == INPUT_SYMBOL)
    {
        for (size_t i = 0; i < sizeof others / sizeof others[0]; i++)
            if (others[i].key == key)
                return mode == INPUT_DIGIT ? others[i].digit : others[i].symbol;
        return 0;
    }
    if (key >= 64 || !letters[key])
        return 0;
    if (mode == INPUT_UPPER && letters[key] != ' ')
        return (char)(letters[key] - 'a' + 'A');
    return letters[key];
}

static void draw_edit(const char *title, const char *value, int mode, bool secret, bool reveal)
{
    char masked[72];
    char mode_text[24];
    const char *shown = value;
    int x = (UI_WIDTH - DIALOG_W) / 2;
    int field_w = DIALOG_W - 24;
    int y = dialog_open(title, 84);

    if (secret && !reveal)
    {
        size_t len = strlen(value);
        if (len > sizeof masked - 1)
            len = sizeof masked - 1;
        memset(masked, '*', len);
        masked[len] = '\0';
        shown = masked;
    }
    while (shown[0] && (int)gfx_GetStringWidth(shown) > field_w - 12)
        shown++;

    snprintf(mode_text, sizeof mode_text, "Keys: %s", input_mode_names[mode]);
    text(mode_text, x + 12, y + 26, UI_ACCENT);
    if (secret)
        text_right(reveal ? "mode: hide" : "mode: show", x + DIALOG_W - 12, y + 26, 120, UI_MUTED);

    fill(x + 12, y + 38, field_w, 18, UI_BG);
    fill(x + 12, y + 55, field_w, 2, UI_ACCENT);
    text(shown, x + 16, y + 43, UI_TEXT);
    fill(x + 17 + (int)gfx_GetStringWidth(shown), y + 42, 2, 10, UI_ACCENT);
    dialog_keys(y, 84, "alpha: keys  del: erase  enter: OK  clear: cancel");
    ui_present();
}

bool ui_edit_text(const char *title, char *buffer, size_t size, bool secret)
{
    char work[72];
    size_t pos;
    int mode = INPUT_LOWER;
    bool reveal = false;

    if (size > sizeof work)
        size = sizeof work;
    snprintf(work, size, "%s", buffer);
    pos = strlen(work);

    for (;;)
    {
        uint8_t key;
        char c;

        draw_edit(title, work, mode, secret, reveal);
        key = ui_wait_key();
        if (key == sk_Clear)
        {
            tls_secure_memzero(work, sizeof work);
            return false;
        }
        if (key == sk_Enter)
        {
            snprintf(buffer, size, "%s", work);
            tls_secure_memzero(work, sizeof work);
            return true;
        }
        if (key == sk_Del || key == sk_Left)
        {
            if (pos > 0)
                work[--pos] = '\0';
        }
        else if (key == sk_Alpha)
        {
            mode = (mode + 1) % INPUT_MODES;
        }
        else if (key == sk_Mode && secret)
        {
            reveal = !reveal;
        }
        else if ((c = key_to_char(key, mode)) != 0 && pos + 1 < size)
        {
            work[pos++] = c;
            work[pos] = '\0';
        }
    }
}

int ui_choose(const char *title, const char *const *items, int count, int selected)
{
    const int row_h = 16;
    int h = 22 + count * row_h + 18;
    int x = (UI_WIDTH - DIALOG_W) / 2;

    for (;;)
    {
        int y = dialog_open(title, h);

        for (int i = 0; i < count; i++)
        {
            int ry = y + 20 + i * row_h;
            if (i == selected)
            {
                fill(x + 4, ry, DIALOG_W - 8, row_h - 1, UI_SELECT);
                fill(x + 4, ry, 3, row_h - 1, UI_ACCENT);
            }
            text_fit(items[i], x + 14, ry + 4, DIALOG_W - 28, UI_TEXT);
        }
        dialog_keys(y, h, "enter: choose  clear: back");
        ui_present();

        uint8_t key = ui_wait_key();
        if (key == sk_Clear)
            return -1;
        if (key == sk_Enter)
            return selected;
        if (key == sk_Up)
            selected = selected > 0 ? selected - 1 : count - 1;
        if (key == sk_Down)
            selected = selected < count - 1 ? selected + 1 : 0;
    }
}

bool ui_confirm(const char *title, const char *question)
{
    for (;;)
    {
        int y = dialog_open(title, 60);

        text_center(question, UI_WIDTH / 2, y + 28, DIALOG_W - 20, UI_TEXT);
        dialog_keys(y, 60, "enter: yes  clear: no");
        ui_present();

        uint8_t key = ui_wait_key();
        if (key == sk_Enter)
            return true;
        if (key == sk_Clear)
            return false;
    }
}

void ui_message(const char *title, const char *line1, const char *line2)
{
    for (;;)
    {
        int y = dialog_open(title, 70);

        if (line1)
            text_center(line1, UI_WIDTH / 2, y + 26, DIALOG_W - 20, UI_TEXT);
        if (line2)
            text_center(line2, UI_WIDTH / 2, y + 38, DIALOG_W - 20, UI_MUTED);
        dialog_keys(y, 70, "press any key");
        ui_present();
        if (ui_wait_key() != UI_KEY_REDRAW)
            return;
    }
}

void ui_busy(const char *title, const char *message)
{
    int y = dialog_open(title, 50);

    text_center(message, UI_WIDTH / 2, y + 29, DIALOG_W - 20, UI_TEXT);
    ui_present();
}
