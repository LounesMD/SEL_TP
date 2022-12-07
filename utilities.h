#ifndef UTILITIES
#define UTILITIES

int command_writer(char* command, int length_command, char** command_part, int nb_command_part);

int get_pid(char* proc_name, char* pid_char);

long find_addr_fun (char* static_ex_name, char* fun_name);

long function_offset(char* pid, char* function_name);

#endif