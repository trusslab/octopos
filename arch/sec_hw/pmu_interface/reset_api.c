#ifdef 	ARCH_SEC_HW_OS

#include "xgpio_l.h"
#include "xgpio.h"
#include "sleep.h"

#include <arch/sec_hw.h>
#include <arch/reset_api.h>

#include <octopos/mailbox.h>

extern XGpio reset_gpio_0;

void request_pmu_to_reset(uint8_t runtime_proc_id)
{
	if (runtime_proc_id == P_RUNTIME1) {
		/* Reset Microblaze 2 */
		XGpio_DiscreteWrite(&reset_gpio_0, 2, 0xFFFFFFFFU);
		usleep(1);
		XGpio_DiscreteWrite(&reset_gpio_0, 2, 0x00000000U);
		usleep(1);
		XGpio_DiscreteWrite(&reset_gpio_0, 2, 0xFFFFFFFFU);
	} else if (runtime_proc_id == P_RUNTIME2) {
		/* Reset Microblaze 2 */
		XGpio_DiscreteWrite(&reset_gpio_0, 1, 0xFFFFFFFFU);
		usleep(1);
		XGpio_DiscreteWrite(&reset_gpio_0, 1, 0x00000000U);
		usleep(1);
		XGpio_DiscreteWrite(&reset_gpio_0, 1, 0xFFFFFFFFU);
	} 
}

#endif
