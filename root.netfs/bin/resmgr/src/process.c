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

#include <string.h>
#include <signal.h>


#include <emscripten.h>

#define NO_PARENT 0

#define RESMGR_ID 1
#define TTY_ID    2
#define NETFS_ID  3
#define INIT_ID   4

static struct process processes[NB_PROCESSES_MAX];
static int nb_processes = 0;

static struct vnode * vfs_proc;

pid_t fork_process(pid_t pid, pid_t ppid, const char * name, const char * cwd);

void process_init() {

  struct vnode * vnode = vfs_find_node("/");

  // Add /proc
  vfs_proc = vfs_add_dir(vnode,"proc");

  for (int i = 0; i < NB_PROCESSES_MAX; ++i) {

    processes[i].pid = -1;
  }

  fork_process(RESMGR_ID, NO_PARENT, "resmgr", "/bin/resmgr");
}

pid_t create_tty_process() {

  fork_process(TTY_ID, NO_PARENT, "tty", "/bin/tty");

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

  fork_process(NETFS_ID, NO_PARENT, "netfs", "/bin/netfs");
  
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

  fork_process(INIT_ID, NO_PARENT, "init", "/bin/init");
  
  pid_t pid = fork();
  
  if (pid == -1) { // Error
    
    emscripten_log(EM_LOG_CONSOLE,"Error while creating init process ...");
    return -1;
    
  } else if (pid == 0) { // Child process

    emscripten_log(EM_LOG_CONSOLE,"starting init process...");

    execl ("/bin/sysvinit", "init", (void*)0);
    
  } else { // Parent process
    
    emscripten_log(EM_LOG_CONSOLE,"init process created: %d",pid);

    return pid;
  }

  return 0;
}

pid_t fork_process(pid_t pid, pid_t ppid, const char * name, const char * cwd) {

  if (pid < 0)
    pid = nb_processes;
  else
    nb_processes = pid;

  if (pid >= NB_PROCESSES_MAX)
    return -1;

  processes[pid].proc_state = RUNNING_STATE;
  
  processes[pid].pid = pid;
  processes[pid].ppid = ppid;

  if (ppid >= 0) {

    processes[pid].pgid =  processes[ppid].pgid;
    processes[pid].sid =  processes[ppid].sid;
    processes[pid].term =  processes[ppid].term;
    
  }
  else {

    processes[pid].pgid = 0;
    processes[pid].sid = 0;
    processes[pid].term =  NULL;
  }

  strcpy(processes[pid].name, name);
  strcpy(processes[pid].cwd, cwd);

  if (ppid >= 0) {
    processes[pid].umask = processes[ppid].umask;
    memcpy(&processes[pid].sigprocmask, &processes[ppid].sigprocmask, sizeof(sigset_t));
  }

  sigemptyset(&processes[pid].pendingsig);
    
  for (int i = 0; i < NB_FILES_MAX; ++i) {

    processes[pid].fds[i].fd = -1;
  }

  processes[pid].peer_addr.sun_family = AF_UNIX;
  sprintf(processes[pid].peer_addr.sun_path, "channel.process.%d", pid);

  processes[pid].last_fd = 2;

  if (ppid > 0) {

    processes[pid].last_fd = processes[ppid].last_fd;

    for (int i = 0; i < NB_FILES_MAX; ++i) {

      if (processes[ppid].fds[i].fd >= 0) {
	
	processes[pid].fds[i].fd = processes[ppid].fds[i].fd;
	processes[pid].fds[i].remote_fd = processes[ppid].fds[i].remote_fd;
	processes[pid].fds[i].type = processes[ppid].fds[i].type;
	processes[pid].fds[i].major = processes[ppid].fds[i].major;
	processes[pid].fds[i].minor = processes[ppid].fds[i].minor;
	strcpy(processes[pid].fds[i].peer, processes[ppid].fds[i].peer);
      }
    }
  }
  
  ++nb_processes;

  return pid;
}

void dump_processes() {

  emscripten_log(EM_LOG_CONSOLE,"**** processes ****");

  for (int i = 0; i < nb_processes; ++i) {

    emscripten_log(EM_LOG_CONSOLE, "* %d %d %s %d", processes[i].pid, processes[i].ppid, processes[i].name, processes[i].proc_state);
  }
}

int process_create_fd(pid_t pid, int remote_fd, unsigned char type, unsigned short major, unsigned short minor) {
  
  int i;
  
  for (i = 0; i < NB_FILES_MAX; ++i) {

    if (processes[pid].fds[i].fd == -1)
      break;
  }

  if (i >= NB_FILES_MAX)
    return -1;

  processes[pid].last_fd++;

  processes[pid].fds[i].fd = processes[pid].last_fd;
  processes[pid].fds[i].remote_fd = remote_fd;
  processes[pid].fds[i].type = type;
  processes[pid].fds[i].major = major;
  processes[pid].fds[i].minor = minor;

  return processes[pid].last_fd;
}

int process_get_fd(pid_t pid, int fd, unsigned char * type, unsigned short * major, int * remote_fd) {

  for (int i = 0; i < NB_FILES_MAX; ++i) {

    if (processes[pid].fds[i].fd == fd) {
      *type = processes[pid].fds[i].type;
      *major = processes[pid].fds[i].major;
      *remote_fd = processes[pid].fds[i].minor;

      return 0;
    }
  }

  return -1;
}

int process_close_fd(pid_t pid, int fd) {

  for (int i = 0; i < NB_FILES_MAX; ++i) {

    if (processes[pid].fds[i].fd == fd) {

      processes[pid].fds[i].fd = -1;
      
      return 0;
    }
  }

  return -1;
}

int process_find_open_fd(unsigned char type, unsigned short major, int remote_fd) {

  for (int j = 0; j < nb_processes; ++j) {

    for (int i = 0; i < NB_FILES_MAX; ++i) {

      if (processes[j].fds[i].fd != -1) {

	if ( (processes[j].fds[i].type == type) && (processes[j].fds[i].major == major) && (processes[j].fds[i].remote_fd == remote_fd) ) {

	  return 1;
	  
	}
      }
    }
  }

  return 0;
}

struct sockaddr_un * process_get_peer_addr(pid_t pid) {

  return &processes[pid].peer_addr;
}

pid_t process_group_exists(pid_t pgid) {

  for (int i = 0; i < nb_processes; ++i) {

    if (processes[i].pgid == pgid)
      return i;
  }

  return 0;
}

pid_t process_setsid(pid_t pid) {

  if (!process_group_exists(pid)) { // process is not process group leader

    processes[pid].pgid = pid;
    processes[pid].sid = pid;
    processes[pid].term = NULL;
    
    return pid;
  }

  return -1;
}

