#ifndef __SEC_HW_PMU_RESET_API_H
#define __SEC_HW_PMU_RESET_API_H

#define RESP_AND_MSG_NUM_OFFSET		0x1U
#define IPI_HEADER_OFFSET			0x0U
#define IPI_HEADER					0x1E0000 /* 1E - Target Module ID */

void request_pmu_to_reset(uint8_t runtime_proc_id);

#endif /* __SEC_HW_PMU_RESET_API_H */
