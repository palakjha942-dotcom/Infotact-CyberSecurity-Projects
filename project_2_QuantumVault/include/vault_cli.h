#ifndef VAULT_CLI_H
#define VAULT_CLI_H

typedef enum {
    CMD_HELP,
    CMD_MOUNT,
    CMD_UNMOUNT,
    CMD_STATUS,
    CMD_UNKNOWN
} cli_cmd_t;

typedef struct {
    cli_cmd_t cmd;
    char mount_point[256];
    char storage_dir[256];
} cli_options_t;

/* Parse command-line flags and parameters */
int parse_cli_args(int argc, char *argv[], cli_options_t *opts);

/* Display usage guide */
void print_cli_help(const char *prog_name);

#endif /* VAULT_CLI_H */
