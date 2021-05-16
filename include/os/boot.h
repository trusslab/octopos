#ifndef _OS_BOOT_H_
#define _OS_BOOT_H_

void help_boot_runtime_proc(uint8_t runtime_proc_id);
void help_boot_procs(int boot_untrusted);
int reset_proc(uint8_t proc_id);
int reset_proc_simple(uint8_t proc_id);
int reboot_system(void);
int halt_system(void);

#endif
