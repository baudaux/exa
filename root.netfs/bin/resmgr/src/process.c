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

#include "process.h"
#include "vfs.h"

#include <emscripten.h>

static struct process processes[NB_PROCESS_MAX];
static int nb_processes = 0;

static struct vnode * vfs_proc;

void add_process(pid_t id, pid_t parent_id);

void process_init() {

  struct vnode * vnode = vfs_find_node("/");

  // Add /proc
  vfs_proc = vfs_add_dir(vnode,"proc");

  add_process(RESMGR_ID,NO_PARENT);
}

pid_t create_tmpfs_process() {

  pid_t pid = fork();
  
  if (pid == -1) { // Error
    
    emscripten_log(EM_LOG_CONSOLE,"Error while creating tmpfs process ...");
    return -1;
    
  } else if (pid == 0) { // Child process

    emscripten_log(EM_LOG_CONSOLE,"starting tmpfs process...");

    execl ("/bin/tmpfs", "tmpfs", (void*)0);
    
  } else { // Parent process

    emscripten_log(EM_LOG_CONSOLE,"tmpfs process created: %d",pid);

    return pid;
  }

  return 0;
}

pid_t create_tty_process() {

  pid_t pid = fork();
  
  if (pid == -1) { // Error
    
    emscripten_log(EM_LOG_CONSOLE,"Error while creating tty process ...");
    return -1;
    
  } else if (pid == 0) { // Child process

    emscripten_log(EM_LOG_CONSOLE,"starting tty process...");

    execl ("/bin/tty", "tty", (void*)0);
    
  } else { // Parent process

    emscripten_log(EM_LOG_CONSOLE,"tty process created: %d",pid);

    return pid;
  }

  return 0;
}

pid_t create_netfs_process() {

  pid_t pid = fork();
  
  if (pid == -1) { // Error
    
    emscripten_log(EM_LOG_CONSOLE,"Error while creating netfs process ...");
    return -1;
    
  } else if (pid == 0) { // Child process

    emscripten_log(EM_LOG_CONSOLE,"starting netfs process...");

    execl ("/bin/netfs", "netfs", (void*)0);
    
  } else { // Parent process
    
    emscripten_log(EM_LOG_CONSOLE,"netfs process created: %d",pid);

    return pid;
  }

  return 0;
}

pid_t create_init_process() {

  return 0;
}

void add_process(pid_t id, pid_t parent_id) {

  processes[nb_processes].id = id;
  processes[nb_processes].parent_id = parent_id;
  
  ++nb_processes;
}
