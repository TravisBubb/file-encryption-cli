#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char CMD_ENCRYPT[] = "encrypt";
static const char CMD_DECRYPT[] = "decrypt";

int cmd_encrypt(int argc, char **argv);
int cmd_decrypt(int argc, char **argv);
int cmd_help(int argc, char **argv);
int print_cmd_usage(const char *cmd);
void print_usage(void);

typedef struct {
  const char *name;
  int (*handler)(int argc, char **argv);
  const char *summary; // Short description for command list
  const char *usage;   // Full usage line
  const char *options; // Detailed options/help
} Command;

static Command commands[] = {
    {"encrypt", cmd_encrypt, "Encrypt a file or string",
     "encryptcli encrypt -f <input> -o <output>",
     "  -f <file>   input file\n"
     "  -o <file>   output file\n"},
    {"decrypt", cmd_decrypt, "Decrypt a file or string",
     "encryptcli decrypt -f <input> -o <output>",
     "  -f <file>   input file\n"
     "  -o <file>   output file\n"},
    {"help", cmd_help, "Show this help message", "encryptcli help [command]",
     "  command    show help for specific command\n"},
    {NULL, NULL, NULL, NULL, NULL} // terminator
};

int dispatch_command(int argc, char **argv) {
  if (argc < 2) {
    print_usage();
    return 1;
  }

  const char *cmd = argv[1];
  for (const Command *c = commands; c->name != NULL; c++) {
    if (strcmp(cmd, c->name) == 0) {
      return c->handler(argc - 1, argv + 1);
    }
  }

  fprintf(stderr, "Unknown command: %s\n\n", cmd);
  print_usage();
  return 2;
}

int main(int argc, char **argv) { return dispatch_command(argc, argv); }

int cmd_encrypt(int argc, char **argv) {
  int opt;
  char *input = NULL;
  char *output = NULL;

  // Reset getopt's global state
  optind = 1;

  while ((opt = getopt(argc, argv, "f:o:")) != -1) {
    switch (opt) {
    case 'f':
      input = optarg;
      break;
    case 'o':
      output = optarg;
      break;
    default:
      print_cmd_usage(CMD_ENCRYPT);
      return 1;
    }
  }

  if (!input || !output) {
    fprintf(stderr, "Missing required options.\n");
    print_cmd_usage(CMD_ENCRYPT);
    return 1;
  }

  printf("Encrypting file: %s -> %s\n", input, output);
  return 0;
}

int cmd_decrypt(int argc, char **argv) { return 0; }

int cmd_help(int argc, char **argv) {
  if (argc < 2) {
    print_usage();
    return 0;
  }
  return print_cmd_usage(argv[1]);
}

int print_cmd_usage(const char *cmd) {
  for (const Command *c = commands; c->name != NULL; c++) {
    if (strcmp(cmd, c->name) == 0) {
      printf("%s - %s\n\nUsage: %s\n\nOptions:\n%s\n", c->name, c->summary,
             c->usage, c->options);
      return 0;
    }
  }
  fprintf(stderr, "Unknown command: %s\n", cmd);
  return 2;
}

void print_usage(void) {
  printf("Usage: encryptcli <command> [OPTIONS]\n\n");
  printf("Commands:\n");
  for (const Command *c = commands; c->name != NULL; c++) {
    printf("  %-10s - %s\n", c->name, c->summary);
  }
  printf("\nRun 'encryptcli help <command>' for more details.\n");
}
