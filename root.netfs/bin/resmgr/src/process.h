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
#include <sys/socket.h>
#include <sys/un.h>

#include "vfs.h"

#define NB_PROCESSES_MAX  64
#define NB_FILES_MAX      64

struct file_desc {

  int fd;
  int remote_fd;            // -2 for socket
  unsigned char type;       // type for socket
  unsigned short major;     // domain for socket
  unsigned short minor;     // protocol for socket

  //char peer[108];
};

enum proc_state {

  RUNNING_STATE = 0,
  SLEEPING_STATE,
  STOPPED_STATE,
  ZOMBIE_STATE
};

struct process {

  char name[16];
  char cwd[1024];
  enum proc_state proc_state;
  pid_t pid;                     // process pid
  pid_t ppid;                    // parent process id
  pid_t pgid;                    // process group id
  pid_t sid;                     // session id

  struct vnode * term;           // controlling terminal

  mode_t umask;
  sigset_t sigprocmask;
  sigset_t pendingsig;
  
  struct sockaddr_un peer_addr;
  
  struct file_desc fds[NB_FILES_MAX];

  unsigned char fd_map[NB_FILES_MAX/8+1];
};

void process_init();

pid_t process_fork(pid_t pid, pid_t ppid, const char * name, const char * cwd);

pid_t create_tty_process();
pid_t create_netfs_process();
pid_t create_init_process();

int process_create_fd(pid_t pid, int remote_fd, unsigned char type, unsigned short major, unsigned short minor);
int process_get_fd(pid_t pid, int fd, unsigned char * type, unsigned short * major, int * remote_fd);
int process_close_fd(pid_t pid, int fd);
int process_find_open_fd(unsigned char type, unsigned short major, int remote_fd);

struct sockaddr_un * process_get_peer_addr(pid_t pid);

pid_t process_setsid(pid_t pid);
pid_t process_getsid(pid_t pid);

pid_t process_getppid(pid_t pid);
pid_t process_getpgid(pid_t pid);
int process_setpgid(pid_t pid, pid_t pgid);

int process_set_ctty(pid_t pid, struct vnode * tty);

int process_dup(pid_t pid, int fd, int new_fd);

void dump_processes();

#endif // _PROCESS_H
