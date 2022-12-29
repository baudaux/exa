/*
 * Copyright (C) 2022 Benoit Baudaux
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
  
};

void process_init();

pid_t create_tmpfs_process();
pid_t create_tty_process();
pid_t create_netfs_process();
pid_t create_init_process();

#endif // _PROCESS_H
