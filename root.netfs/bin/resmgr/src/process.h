/*
 * Copyright (C) 2023 Benoit Baudaux
 *
 * This file is part of EXA.
 *
 * EXA is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * EXA is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with EXA. If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef _PROCESS_H
#define _PROCESS_H

#include <unistd.h>
#include <sys/types.h>

#define NB_PROCESS_MAX 64

#define NO_PARENT -1
#define RESMGR_ID 1

struct process {

  pid_t id;
  pid_t parent_id;

  mode_t umask;
  
};

void process_init();

pid_t create_tty_process();
pid_t create_netfs_process();
pid_t create_init_process();

#endif // _PROCESS_H
