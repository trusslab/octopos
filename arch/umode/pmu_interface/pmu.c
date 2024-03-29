/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
/* OctopOS PMU interface */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arch/pmu.h> 

int fd_pmu_to_os, fd_pmu_from_os;

int pmu_shutdown(void)
{
	uint8_t buf[PMU_OS_BUF_SIZE];
	uint32_t ret;

	buf[0] = PMU_OS_CMD_SHUTDOWN;
	write(fd_pmu_from_os, buf, PMU_OS_BUF_SIZE);
	read(fd_pmu_to_os, &ret, 4);

	if (ret) {
		printf("Error: %s: shutdown failed (%d)\n", __func__, (int) ret);
		return (int) ret;
	}
 
	close(fd_pmu_from_os);
	close(fd_pmu_to_os);

	remove(FIFO_PMU_FROM_OS);
	remove(FIFO_PMU_TO_OS);

	return 0;
}

int pmu_reboot(void)
{
	uint8_t buf[PMU_OS_BUF_SIZE];
	uint32_t ret;

	buf[0] = PMU_OS_CMD_REBOOT;
	write(fd_pmu_from_os, buf, PMU_OS_BUF_SIZE);
	read(fd_pmu_to_os, &ret, 4);

	if (ret) {
		printf("Error: %s: reboot failed (%d)\n", __func__, (int) ret);
		return (int) ret;
	}
 
	return 0;
}

int pmu_reset_proc(uint8_t proc_id)
{
	uint8_t buf[PMU_OS_BUF_SIZE];
	uint32_t ret;

	buf[0] = PMU_OS_CMD_RESET_PROC;
	buf[1] = proc_id;
	write(fd_pmu_from_os, buf, PMU_OS_BUF_SIZE);
	read(fd_pmu_to_os, &ret, 4);

	if (ret) {
		printf("Error: %s: reset proc %d failed (%d)\n",
		       __func__, proc_id, (int) ret);
		return (int) ret;
	}
 
	return 0;
}


void connect_to_pmu(void)
{
	mkfifo(FIFO_PMU_TO_OS, 0666);
	mkfifo(FIFO_PMU_FROM_OS, 0666);

	fd_pmu_to_os = open(FIFO_PMU_TO_OS, O_RDONLY);
	fd_pmu_from_os = open(FIFO_PMU_FROM_OS, O_WRONLY);
}
