/********************************************************************
 * Copyright (c) 2019 - 2023, The OctopOS Authors
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 ********************************************************************/
struct command {
	int cmd_num;
	void (*cmd_func)(int, char **);
	char *cmd_str;
	char *cmd_help;
};

#define CMD_NONUM -1	/* Arguments is parsed in command function. */

