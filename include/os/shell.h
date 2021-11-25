void inform_shell_of_termination(uint8_t runtime_proc_id);
void inform_shell_of_pause(uint8_t runtime_proc_id);
int app_write_to_shell(struct app *app, uint8_t *data, int size);
int untrusted_write_to_shell(uint8_t *data, int size);
int app_read_from_shell(struct app *app);
void shell_serial_out_needs_reset(void);
void initialize_shell(void);
void shell_process_input(char buf);
