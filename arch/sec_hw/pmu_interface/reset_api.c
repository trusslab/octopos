#ifdef 	ARCH_SEC_HW_OS

#include "xipipsu.h"
#include "xgpio_l.h"
#include "xgpio.h"
#include "sleep.h"

#include <arch/sec_hw.h>
#include <arch/reset_api.h>

#include <octopos/mailbox.h>

extern XIpiPsu ipi_pmu_inst;
extern XGpio reset_gpio_0;

void request_pmu_to_reset(uint8_t runtime_proc_id)
{
//	 XGpio_DiscreteWrite(&reset_gpio_0, 1, 0xFFFFFFFFU);
//	 usleep(100);
//	 XGpio_DiscreteWrite(&reset_gpio_0, 1, 0x00000000U);
//	 usleep(100);
//	 XGpio_DiscreteWrite(&reset_gpio_0, 1, 0xFFFFFFFFU);
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

//	/* Send IPI to PMU, PMU will reset the runtime */
//	u32 pmu_ipi_status = XST_FAILURE;
//
//	static u32 MsgPtr[2] = {IPI_HEADER, 0U};
//	/* Convert from proc id to runtime number */
//	_SEC_HW_ERROR("Resetting %d", runtime_proc_id);
//	MsgPtr[RESP_AND_MSG_NUM_OFFSET] = runtime_proc_id - 6;
//	pmu_ipi_status = XIpiPsu_WriteMessage(&ipi_pmu_inst, XPAR_XIPIPS_TARGET_PSU_PMU_0_CH0_MASK,
//			MsgPtr, 2U, XIPIPSU_BUF_TYPE_MSG);
//
//	if(pmu_ipi_status != (u32)XST_SUCCESS) {
//		_SEC_HW_ERROR("RPU: IPI Write message failed");
//		return;
//	}
//
//	pmu_ipi_status = XIpiPsu_TriggerIpi(&ipi_pmu_inst, XPAR_XIPIPS_TARGET_PSU_PMU_0_CH0_MASK);
//
//	if(pmu_ipi_status != (u32)XST_SUCCESS) {
//		_SEC_HW_ERROR("RPU: IPI Trigger failed");
//		return;
//	}
//
//	pmu_ipi_status = XIpiPsu_PollForAck(&ipi_pmu_inst, XPAR_XIPIPS_TARGET_PSU_PMU_0_CH1_MASK, (~0));
//
//	if(pmu_ipi_status != (u32)XST_SUCCESS) {
//		_SEC_HW_ERROR("RPU: IPI Poll for ack failed");
//		return;
//	}
}

#endif
