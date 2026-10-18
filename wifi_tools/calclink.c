#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ticalcs.h>

#define KEY_QUIT 0x0040
#define KEY_CLEAR 0x0009
#define KEY_ENTER 0x0005
#define KEY_2 0x0090
#define KEY_GARBAGE_COLLECT 0xFCFC
#define KEY_PRGM 0x002D
#define KEY_DOWN 0x0004

static CableHandle *cable;
static CalcHandle *calc;

static int fail(int err, const char *what)
{
    char *message = NULL;

    if (err == 0) {
        return 0;
    }

    ticalcs_error_get(err, &message);
    fprintf(stderr, "calclink: %s: %s\n", what, message != NULL ? message : "error");
    g_free(message);
    return err;
}

static int connect_calc(void)
{
    CalcModel model = CALC_NONE;

    ticables_library_init();
    tifiles_library_init();
    ticalcs_library_init();

    cable = ticables_handle_new(CABLE_USB, PORT_1);
    if (cable == NULL) {
        fprintf(stderr, "calclink: no usb cable\n");
        return 1;
    }
    ticables_options_set_timeout(cable, 50);

    if (ticables_cable_open(cable) != 0) {
        fprintf(stderr, "calclink: cannot open calculator, is it plugged in?\n");
        return 1;
    }
    if (ticalcs_probe_usb_calc(cable, &model) != 0 || model != CALC_TI84PCE_USB) {
        fprintf(stderr, "calclink: no TI-84 Plus CE found\n");
        return 1;
    }
    ticables_cable_close(cable);

    calc = ticalcs_handle_new(model);
    if (fail(ticalcs_cable_attach(calc, cable), "attach")) {
        return 1;
    }

    ticables_cable_reset(cable);
    usleep(500000);
    return fail(ticalcs_calc_isready(calc), "calculator not ready");
}

static void disconnect_calc(void)
{
    if (calc != NULL) {
        ticalcs_cable_detach(calc);
        ticalcs_handle_del(calc);
    }
    if (cable != NULL) {
        ticables_handle_del(cable);
    }
}

static int keys(const unsigned *list, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        int err = ticalcs_calc_send_key(calc, list[i]);

        if (err != 0) {
            return fail(err, "send key");
        }
        usleep(150000);
    }

    return 0;
}

static int wait_ready(unsigned seconds)
{
    for (unsigned tries = 0; tries < seconds * 2; tries++) {
        if (ticalcs_calc_isready(calc) == 0) {
            return 0;
        }
        usleep(500000);
    }

    fprintf(stderr, "calclink: calculator did not come back\n");
    return 1;
}

static int home(void)
{
    static const unsigned seq[] = {KEY_QUIT, KEY_CLEAR, KEY_CLEAR};

    if (keys(seq, sizeof seq / sizeof seq[0]) == 0) {
        return 0;
    }

    ticables_cable_reset(cable);
    sleep(1);
    return keys(seq, sizeof seq / sizeof seq[0]);
}

static int garbage_collect(void)
{
    static const unsigned seq[] = {KEY_GARBAGE_COLLECT, KEY_ENTER, KEY_2};
    int err = home();

    if (err == 0) {
        err = keys(seq, sizeof seq / sizeof seq[0]);
    }
    if (err == 0) {
        sleep(2);
        err = wait_ready(120);
    }
    if (err == 0) {
        err = home();
    }

    return err;
}

static int send_file(const char *path)
{
    int err;

    printf("calclink: sending %s\n", path);
    if (tifiles_file_is_app(path)) {
        err = ticalcs_calc_send_app2(calc, path);
    } else {
        err = ticalcs_calc_send_var2(calc, MODE_NORMAL, path);
    }

    return fail(err, path);
}

static int find(const char *name, int apps_only, VarEntry *out)
{
    GNode *vars = NULL;
    GNode *apps = NULL;
    VarEntry wanted;
    VarEntry *found = NULL;
    int err = ticalcs_calc_get_dirlist(calc, &vars, &apps);

    if (err != 0) {
        return -fail(err, "dirlist");
    }

    memset(&wanted, 0, sizeof wanted);
    strncpy(wanted.name, name, sizeof wanted.name - 1);

    if (apps_only) {
        wanted.type = TI84p_APPL;
        found = ticalcs_dirlist_ve_exist(apps, &wanted);
    } else {
        wanted.type = TI84p_ASM;
        found = ticalcs_dirlist_ve_exist(vars, &wanted);
        if (found == NULL) {
            wanted.type = TI84p_PRGM;
            found = ticalcs_dirlist_ve_exist(vars, &wanted);
        }
    }

    if (found != NULL && out != NULL) {
        *out = *found;
        out->data = NULL;
    }

    ticalcs_dirlist_destroy(&vars);
    ticalcs_dirlist_destroy(&apps);
    return found != NULL;
}

static int menu_position(const char *name)
{
    GNode *vars = NULL;
    GNode *apps = NULL;
    int before = 0;
    int err = ticalcs_calc_get_dirlist(calc, &vars, &apps);

    if (err != 0) {
        return -fail(err, "dirlist");
    }

    for (GNode *folder = g_node_first_child(vars); folder != NULL; folder = g_node_next_sibling(folder)) {
        for (GNode *node = g_node_first_child(folder); node != NULL; node = g_node_next_sibling(node)) {
            VarEntry *ve = node->data;

            if (ve != NULL && (ve->type == TI84p_PRGM || ve->type == TI84p_ASM) &&
                strcmp(ve->name, name) < 0) {
                before++;
            }
        }
    }

    ticalcs_dirlist_destroy(&vars);
    ticalcs_dirlist_destroy(&apps);
    return before;
}

static int run_program(const char *arg)
{
    char name[VARNAME_MAX] = {0};
    int position;

    if (tifiles_file_is_regular(arg)) {
        FileContent *content = tifiles_content_create_regular(CALC_TI84PCE_USB);

        if (tifiles_file_read_regular(arg, content) != 0 || content->num_entries == 0) {
            fprintf(stderr, "calclink: cannot read %s\n", arg);
            tifiles_content_delete_regular(content);
            return 1;
        }
        memcpy(name, content->entries[0]->name, sizeof name - 1);
        tifiles_content_delete_regular(content);
    } else {
        strncpy(name, arg, sizeof name - 1);
    }

    if (name[0] < 'A' || name[0] > 'Z') {
        fprintf(stderr, "calclink: cannot type program name %s\n", name);
        return 1;
    }
    if (find(name, 0, NULL) != 1) {
        fprintf(stderr, "calclink: program %s not on calculator\n", name);
        return 1;
    }

    position = menu_position(name);
    if (position < 0) {
        return 1;
    }

    printf("calclink: running %s\n", name);
    {
        int err = home();

        if (err == 0) {
            err = keys((unsigned[]){KEY_PRGM}, 1);
        }
        while (err == 0 && position-- > 0) {
            err = keys((unsigned[]){KEY_DOWN}, 1);
        }
        if (err == 0) {
            err = keys((unsigned[]){KEY_ENTER}, 1);
        }
        if (err == 0) {
            ticalcs_calc_send_key(calc, KEY_ENTER);
        }
        return err;
    }
}

static int delete_app(const char *name)
{
    VarEntry entry;
    int found = find(name, 1, &entry);

    if (found <= 0) {
        return found < 0;
    }

    printf("calclink: deleting app %s\n", name);
    return fail(ticalcs_calc_del_var(calc, &entry), "delete app");
}

static int list_vars(void)
{
    GNode *vars = NULL;
    GNode *apps = NULL;
    int err = ticalcs_calc_get_dirlist(calc, &vars, &apps);

    if (err != 0) {
        return fail(err, "dirlist");
    }

    for (GNode *tree = vars; tree != NULL; tree = tree == vars ? apps : NULL) {
        for (GNode *folder = g_node_first_child(tree); folder != NULL; folder = g_node_next_sibling(folder)) {
            for (GNode *node = g_node_first_child(folder); node != NULL; node = g_node_next_sibling(node)) {
                VarEntry *ve = node->data;

                if (ve != NULL) {
                    printf("%-8s %s %u%s\n", ve->name, tifiles_vartype2string(CALC_TI84PCE_USB, ve->type),
                           ve->size, ve->attr == ATTRB_ARCHIVED ? " archived" : "");
                }
            }
        }
    }

    ticalcs_dirlist_destroy(&vars);
    ticalcs_dirlist_destroy(&apps);
    return 0;
}

static int get_var(const char *name, const char *path)
{
    VarEntry entry;
    GNode *vars = NULL;
    GNode *apps = NULL;
    VarEntry *found;
    int err = ticalcs_calc_get_dirlist(calc, &vars, &apps);

    if (err != 0) {
        return fail(err, "dirlist");
    }

    memset(&entry, 0, sizeof entry);
    strncpy(entry.name, name, sizeof entry.name - 1);
    entry.type = TI84p_APPV;
    found = ticalcs_dirlist_ve_exist(vars, &entry);
    if (found != NULL) {
        entry = *found;
    }
    ticalcs_dirlist_destroy(&vars);
    ticalcs_dirlist_destroy(&apps);

    if (found == NULL) {
        fprintf(stderr, "calclink: %s not on calculator\n", name);
        return 1;
    }
    return fail(ticalcs_calc_recv_var2(calc, MODE_NORMAL, path, &entry), "get");
}

static int screenshot(const char *path)
{
    CalcScreenCoord coord = {SCREEN_FULL, 0, 0, 0, 0, CALC_PIXFMT_RGB_565_LE};
    uint8_t *bitmap = NULL;
    int err = ticalcs_calc_recv_screen_rgb888(calc, &coord, &bitmap);
    FILE *out;

    if (err != 0) {
        return fail(err, "screenshot");
    }

    out = fopen(path, "wb");
    if (out == NULL) {
        perror(path);
        ticalcs_free_screen(bitmap);
        return 1;
    }
    fprintf(out, "P6\n%u %u\n255\n", coord.width, coord.height);
    fwrite(bitmap, 3, (size_t)coord.width * coord.height, out);
    fclose(out);
    ticalcs_free_screen(bitmap);
    return 0;
}

static int usage(void)
{
    fprintf(stderr,
            "usage: calclink gc\n"
            "       calclink send FILE...\n"
            "       calclink run PROGRAM|FILE.8xp\n"
            "       calclink wait SECONDS\n"
            "       calclink has-app NAME\n"
            "       calclink del-app NAME\n"
            "       calclink screenshot FILE.ppm\n"
            "       calclink ls\n"
            "       calclink get APPVAR FILE.8xv\n"
            "       calclink key CODE...\n");
    return 2;
}

int main(int argc, char **argv)
{
    int err = 0;

    if (argc < 2) {
        return usage();
    }
    if (connect_calc() != 0) {
        disconnect_calc();
        return 1;
    }

    if (strcmp(argv[1], "gc") == 0 && argc == 2) {
        printf("calclink: garbage collect\n");
        err = garbage_collect();
    } else if (strcmp(argv[1], "send") == 0 && argc > 2) {
        for (int i = 2; i < argc && err == 0; i++) {
            err = send_file(argv[i]);
        }
    } else if (strcmp(argv[1], "run") == 0 && argc == 3) {
        err = run_program(argv[2]);
    } else if (strcmp(argv[1], "wait") == 0 && argc == 3) {
        sleep(2);
        err = wait_ready((unsigned)atoi(argv[2]));
    } else if (strcmp(argv[1], "has-app") == 0 && argc == 3) {
        int found = find(argv[2], 1, NULL);
        err = found < 0 ? 2 : !found;
    } else if (strcmp(argv[1], "del-app") == 0 && argc == 3) {
        err = delete_app(argv[2]);
    } else if (strcmp(argv[1], "key") == 0 && argc > 2) {
        for (int i = 2; i < argc && err == 0; i++) {
            unsigned code = (unsigned)strtoul(argv[i], NULL, 0);
            err = keys(&code, 1);
        }
    } else if (strcmp(argv[1], "get") == 0 && argc == 4) {
        err = get_var(argv[2], argv[3]);
    } else if (strcmp(argv[1], "ls") == 0 && argc == 2) {
        err = list_vars();
    } else if (strcmp(argv[1], "screenshot") == 0 && argc == 3) {
        err = screenshot(argv[2]);
    } else {
        err = usage();
    }

    disconnect_calc();
    return err != 0;
}
