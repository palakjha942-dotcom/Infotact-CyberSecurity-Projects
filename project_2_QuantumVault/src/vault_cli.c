#include "vault_cli.h"
#include <stdio.h>
#include <string.h>

void print_cli_help(const char *prog_name) {
    printf("QuantumVault - Post-Quantum Encrypted Filesystem CLI\n");
    printf("Usage:\n");
    printf("  %s mount <storage_dir> <mount_point>\n", prog_name);
    printf("  %s unmount <mount_point>\n", prog_name);
    printf("  %s status\n", prog_name);
    printf("  %s help\n", prog_name);
}

int parse_cli_args(int argc, char *argv[], cli_options_t *opts) {
    if (!opts || argc < 2) return -1;
    memset(opts, 0, sizeof(cli_options_t));

    if (strcmp(argv[1], "mount") == 0) {
        if (argc < 4) return -1;
        opts->cmd = CMD_MOUNT;
        strncpy(opts->storage_dir, argv[2], sizeof(opts->storage_dir) - 1);
        strncpy(opts->mount_point, argv[3], sizeof(opts->mount_point) - 1);
        return 0;
    } else if (strcmp(argv[1], "unmount") == 0) {
        if (argc < 3) return -1;
        opts->cmd = CMD_UNMOUNT;
        strncpy(opts->mount_point, argv[2], sizeof(opts->mount_point) - 1);
        return 0;
    } else if (strcmp(argv[1], "status") == 0) {
        opts->cmd = CMD_STATUS;
        return 0;
    } else if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0) {
        opts->cmd = CMD_HELP;
        return 0;
    }

    opts->cmd = CMD_UNKNOWN;
    return -1;
}
