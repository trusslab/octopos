#include <stdio.h>
#include <tpm/tpm.h>


void tpm_monitor_core()
{
    /* TODO: use mailbox to auto monitor */
    uint8_t slot = 0;
    while (1)
    {
        fscanf(stdin, "%d", &slot);
        fflush(stdin);
        if (slot >= 0 && slot <= 23)
            pcr_read_single(slot);
    }
}

int main(int argc, char const *argv[])
{
    tpm_monitor_core();
    
    return 0;
}
