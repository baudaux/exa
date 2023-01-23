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

#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>

#include <fcntl.h>
#include <errno.h>

#include "vfs.h"
#include "process.h"
#include "device.h"
#include "unordered_map.h"

#include "msg.h"

#include <emscripten.h>

/* Be careful when changing this path as it may be also used in javascript */

#define RESMGR_ROOT "/var"
#define RESMGR_FILE "resmgr.peer"
#define RESMGR_PATH RESMGR_ROOT "/" RESMGR_FILE

static char * starting_exa =  "\r\n"
"              ...                ...              \r\n"
"            .0O0O:'.':..,,,...;'';O0:.            \r\n"
"            0Oo0...'....;.,..'.....0OP.           \r\n"
"            lP:..;..,._....._.,.;..o0p.           \r\n"
"            '........,e),.,(e,....,..i            \r\n"
"             l,..;.....,aaa,..,...;..j            \r\n"
"             i.....(-;:aaaaa;;-):...l             \r\n"
"              (,..:.((..aaa..))..;..)             \r\n"
"               ;......(((O)))..:...!              \r\n"
"       ..'.....'..exa.:.',':.;:os'.:...',,'.      \r\n"
"    ,ldxkxo:...'...';:;axel:':;.;.;...'lkkkxl;.   \r\n"
"  .:00Okxxxd:....,..,..;......'....:..:k00OOOk,,  \r\n"
"  ;.0Okxxxxdo'.,..,..'....:.....;.:...:OKK00Ok,:. \r\n"
"  .:OOkxxdlc,...'..;....'....'..,:..  .;okOOO.;,  \r\n"
"    ';:;,..   ......'..,.;.'..,.,:...    ..''..   \r\n"
"             .;,'...:...,...:......,;.            \r\n"
"            .odl:;,'',,'',''.'..,;clo:.           \r\n"
"           .cxdooolc:;;       ;:cloddddc,'..      \r\n" 
"         .,cdddooool:;        ;ldkkkkkkkkdl,.     \r\n"
"       ,oxxdddddddd:.          ,dO000O00Okxd:.    \r\n"
"      ;kOkddddddddo'            :k0K00K00OOkx,    \r\n"
"      l;;;:;;;:xodo            .lO;,:;:;,:;:0'    \r\n"
"      .;,:;:;,:;:.              .;,:;:;,:;:l.     \r\n"
"        .,..,..,                   ';:::,.        \r\n"
  "\r\n";

int main() {

  int sock;
  struct sockaddr_un local_addr, remote_addr, tty_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1256];

  int execve_size;
  int execve_pid;
  char execve_msg[1256];

  // Use console.log as tty is not yet started
  emscripten_log(EM_LOG_CONSOLE, "Starting resmgr v0.1.0 ...");

  vfs_init();
  process_init();
  device_init();

  /* Create the server local socket */
  sock = socket(AF_UNIX, SOCK_DGRAM, 0);

  // TODO: Add close on exec
  
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sun_family = AF_UNIX;
  strcpy(local_addr.sun_path, RESMGR_PATH);

  /* Bind socket to RESMGR_PATH : path is not created as we are in resmgr ... */
  bind(sock, (struct sockaddr *) &local_addr, sizeof(local_addr));

  /* ... so we need to add it in vfs */
  struct vnode * vnode = vfs_find_node(RESMGR_ROOT);
  vfs_add_file(vnode, RESMGR_FILE);

  /* Register vfs driver */
  unsigned short vfs_major = device_register_driver(FS_DEV, "vfs", RESMGR_PATH);
  unsigned short vfs_minor = 1;

  device_register_device(FS_DEV, vfs_major, vfs_minor, "vfs1");

  // First, we create tty process
  
  create_tty_process();
  
  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, &len);

    struct message * msg = (struct message *)&buf[0];

    //emscripten_log(EM_LOG_CONSOLE, "resmgr: msg %d received from %s (%d)", msg->msg_id, remote_addr.sun_path,bytes_rec);

    if (msg->msg_id == REGISTER_DRIVER) {
      
      emscripten_log(EM_LOG_CONSOLE, "REGISTER_DRIVER %s (%d)", msg->_u.dev_msg.dev_name, msg->_u.dev_msg.dev_type);

      // Add driver
      msg->_u.dev_msg.major = device_register_driver(msg->_u.dev_msg.dev_type, (const char *)msg->_u.dev_msg.dev_name, (const char *)remote_addr.sun_path);
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == REGISTER_DEVICE) {
      
      emscripten_log(EM_LOG_CONSOLE, "REGISTER_DEVICE %s (%d,%d,%d)", msg->_u.dev_msg.dev_name, msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor);

      device_register_device(msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor, (const char *)msg->_u.dev_msg.dev_name);

      char dev_name[DEV_NAME_LENGTH_MAX];
      strcpy(dev_name, (const char *)msg->_u.dev_msg.dev_name);
      unsigned char dev_type = msg->_u.dev_msg.dev_type;

      msg->msg_id |= 0x80;
      msg->_errno = 0;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      if ( (msg->_u.dev_msg.dev_type == CHR_DEV) && (msg->_u.dev_msg.major == 1) && (msg->_u.dev_msg.minor == 1) ) {  // First device is tty

	memcpy(&tty_addr, &remote_addr, sizeof(remote_addr));

	for (int i = 0; i < strlen(starting_exa); ) {
	
	  memset(buf, 0, 1256);
	  msg->msg_id = WRITE;
	  msg->_u.io_msg.fd = -1; // minor == 1

	  int len = (strlen(starting_exa+i) < 1200)?strlen(starting_exa+i):1200;
	  msg->_u.io_msg.len = len;

	  strncpy((char *)msg->_u.io_msg.buf, starting_exa+i, len);
	  ((char *)msg->_u.io_msg.buf)[len] = 0;

	  i += len;

	  sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	}

	create_netfs_process();
      }

      // add char and block devices to /dev
      if ( (dev_type == CHR_DEV) || (dev_type == BLK_DEV) ) {

	  memset(buf, 0, 1256);
	  msg->msg_id = WRITE;
	  msg->_u.io_msg.fd = -1; // minor == 1

	  sprintf((char *)msg->_u.io_msg.buf,"\r\n/dev/%s added", dev_name);

	  msg->_u.io_msg.len = strlen((char *)(msg->_u.io_msg.buf))+1;

	  sendto(sock, buf, 1256, 0, (struct sockaddr *) &tty_addr, sizeof(tty_addr));

	  emscripten_log(EM_LOG_CONSOLE, "Send msg to %s", tty_addr.sun_path);
	}
      
    }
    else if (msg->msg_id == MOUNT) {

      struct device * dev = NULL;
      char pathname[1024];

      emscripten_log(EM_LOG_CONSOLE, "MOUNT %d %d %d %s", msg->_u.mount_msg.dev_type, msg->_u.mount_msg.major, msg->_u.mount_msg.minor, (const char *)&msg->_u.mount_msg.pathname[0]);

      struct vnode * vnode = vfs_find_node((const char *)&msg->_u.mount_msg.pathname[0]);
  
      if (vnode && (vnode->type == VDIR)) {
	vfs_set_mount(vnode, msg->_u.mount_msg.dev_type, msg->_u.mount_msg.major, msg->_u.mount_msg.minor);
	msg->_errno = 0;

	dev = device_get_device(msg->_u.mount_msg.dev_type, msg->_u.mount_msg.major, msg->_u.mount_msg.minor);

	strcpy((char *)&(pathname[0]), (const char *)&(msg->_u.mount_msg.pathname[0]));
      }
      else {
	msg->_errno = ENOTDIR;

	emscripten_log(EM_LOG_CONSOLE, "mount: %s not a directory", msg->_u.mount_msg.pathname);
      }

      msg->msg_id |= 0x80;
      
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      if (msg->_errno == 0) {

	memset(buf, 0, 1256);
	msg->msg_id = WRITE;
	msg->_u.io_msg.fd = -1; // minor == 1

	sprintf((char *)msg->_u.io_msg.buf,"\r\ndevice %s mounted on %s", (const char *)&(dev->name[0]), (const char *)&(pathname[0]));

	msg->_u.io_msg.len = strlen((char *)(msg->_u.io_msg.buf))+1;

	sendto(sock, buf, 1256, 0, (struct sockaddr *) &tty_addr, sizeof(tty_addr));
	emscripten_log(EM_LOG_CONSOLE, "Mount path: %s", pathname);

	if (strcmp((const char *)&(pathname[0]),"/etc") == 0) {

	  memset(buf, 0, 1256);
	  msg->msg_id = WRITE;
	  msg->_u.io_msg.fd = -1; // minor == 1

	  sprintf((char *)msg->_u.io_msg.buf,"\r\nstart sysvinit");

	  msg->_u.io_msg.len = strlen((char *)(msg->_u.io_msg.buf))+1;

	  sendto(sock, buf, 1256, 0, (struct sockaddr *) &tty_addr, sizeof(tty_addr));

	  create_init_process();

	  dump_processes();
	}
      }
    }
    else if (msg->msg_id == SOCKET) {

      msg->msg_id |= 0x80;
      msg->_errno = 0;

      emscripten_log(EM_LOG_CONSOLE, "SOCKET %d %d %d %d", msg->pid, msg->_u.socket_msg.domain, msg->_u.socket_msg.type, msg->_u.socket_msg.protocol);

      msg->_u.socket_msg.fd = process_create_fd(msg->pid, -2, (unsigned char)(msg->_u.socket_msg.type & 0xff), (unsigned short)(msg->_u.socket_msg.domain & 0xffff), (unsigned short)(msg->_u.socket_msg.protocol & 0xffff));

      if (msg->_u.socket_msg.type & SOCK_CLOEXEC) {

	// TODO
      }

      if (msg->_u.socket_msg.type & SOCK_NONBLOCK) {

	// TODO
      }

      emscripten_log(EM_LOG_CONSOLE, "SOCKET created %d", msg->_u.socket_msg.fd);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == BIND) {

      msg->msg_id |= 0x80;
      msg->_errno = 0;

      emscripten_log(EM_LOG_CONSOLE, "BIND %x %s", ((struct sockaddr_un *)&(msg->_u.bind_msg.addr))->sun_family, ((struct sockaddr_un *)&(msg->_u.bind_msg.addr))->sun_path);

      struct vnode * vnode = vfs_find_node((const char *) ((struct sockaddr_un *)&(msg->_u.bind_msg.addr))->sun_path);

      if (vnode) {

	//emscripten_log(EM_LOG_CONSOLE, "vnode found");

	msg->_errno = EADDRINUSE;
      }
      else {

	vnode = vfs_create_file((const char *) ((struct sockaddr_un *)&(msg->_u.bind_msg.addr))->sun_path);

	if (vnode) {

	  //emscripten_log(EM_LOG_CONSOLE, "vnode created");
	}
	else {

	  //emscripten_log(EM_LOG_CONSOLE, "vnode creation error");

	  msg->_errno = EACCES;
	}
      }
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == OPEN) {

      emscripten_log(EM_LOG_CONSOLE, "OPEN from %d: %x %x %s", msg->pid, msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->_u.open_msg.pathname);

      int remote_fd = vfs_open((const char *)msg->_u.open_msg.pathname, msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->pid, vfs_minor);
      
      if (remote_fd == 0) {

	struct vnode * vnode = vfs_get_vnode(remote_fd);

	emscripten_log(EM_LOG_CONSOLE, "vnode is a device or mount point: %d %d %d %s",vnode->_u.dev.type, vnode->_u.dev.major, vnode->_u.dev.minor, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);

	// Forward msg to driver

	msg->_u.open_msg.type = vnode->_u.dev.type;
	msg->_u.open_msg.major = vnode->_u.dev.major;
	msg->_u.open_msg.minor = vnode->_u.dev.minor;
	strcpy((char *)msg->_u.open_msg.peer, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);
	  
	struct sockaddr_un driver_addr;

	driver_addr.sun_family = AF_UNIX;
	strcpy(driver_addr.sun_path, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);

	sendto(sock, buf, 1256, 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));
	  
      }
      else if (remote_fd > 0) {

	msg->msg_id |= 0x80;
	msg->_errno = 0;
	  
	msg->_u.open_msg.remote_fd = remote_fd;
	msg->_u.open_msg.type = FS_DEV;
	msg->_u.open_msg.major = vfs_major;
	msg->_u.open_msg.minor = vfs_minor;
	strcpy((char *)msg->_u.open_msg.peer, RESMGR_PATH);
	  
	msg->_u.open_msg.fd = process_create_fd(msg->pid, msg->_u.open_msg.remote_fd, msg->_u.open_msg.type, msg->_u.open_msg.major, msg->_u.open_msg.minor);

	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      else {

	emscripten_log(EM_LOG_CONSOLE, "vnode not found");

	msg->msg_id |= 0x80;
	msg->_errno = ENOENT;
	
	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
    }
    else if (msg->msg_id == (OPEN|0x80)) {

      emscripten_log(EM_LOG_CONSOLE, "Response from OPEN from %d: %x %x %s %d %d", msg->pid, msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->_u.open_msg.pathname,msg->pid, msg->_u.open_msg.remote_fd);

      if (msg->_errno == 0) {

	msg->_u.open_msg.fd = process_create_fd(msg->pid, msg->_u.open_msg.remote_fd, msg->_u.open_msg.type, msg->_u.open_msg.major, msg->_u.open_msg.minor);

	if ( (msg->_u.open_msg.major == 1) && (!(msg->_u.open_msg.flags & O_NOCTTY )) ) {

	  if (process_set_ctty(msg->pid, vfs_get_vnode(0))) {

	    // TODO: send message to driver
	  }
	}
      }

      // Forward response to process

      sendto(sock, buf, 1256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
      
    }
    else if (msg->msg_id == CLOSE) {

      emscripten_log(EM_LOG_CONSOLE, "CLOSE from %d: %d", msg->pid, msg->_u.close_msg.fd);

      unsigned char type;
      unsigned short major;
      int remote_fd;

      // Get the fd of the process
      if (process_get_fd(msg->pid, msg->_u.close_msg.fd, &type, &major, &remote_fd) >= 0) {

	// Close the fd for this process
	process_close_fd(msg->pid, msg->_u.close_msg.fd);

	// Find fd in other processes
	if (process_find_open_fd(type, major, remote_fd) < 0) {

	  // No more fd, close the fd in the driver

	  // Forward msg to driver

	  msg->_u.close_msg.fd = remote_fd;

	  if (major != vfs_major) {

	    struct sockaddr_un driver_addr;

	    driver_addr.sun_family = AF_UNIX;
	    strcpy(driver_addr.sun_path, device_get_driver(type, major)->peer);

	    emscripten_log(EM_LOG_CONSOLE, "CLOSE send to: %s", driver_addr.sun_path);

	    sendto(sock, buf, 256, 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));
	  }
	  else {

	    msg->msg_id |= 0x80;

	    if (vfs_close(remote_fd) >= 0) {
	      
	      msg->_errno = 0;  
	    }
	    else {

	      msg->_errno = EBADF;
	    }

	    sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	  }
	}
	else {

	  emscripten_log(EM_LOG_CONSOLE, "CLOSE: do not close");

	  // Other fd are there, do not close fd in the driver

	  msg->msg_id |= 0x80;
	  msg->_errno = 0;

	  sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	}
      }
      else {

	emscripten_log(EM_LOG_CONSOLE, "CLOSE: not found");

	msg->msg_id |= 0x80;
	msg->_errno = EBADF;

	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
    }
    else if (msg->msg_id == (CLOSE|0x80)) {

      emscripten_log(EM_LOG_CONSOLE, "Response from CLOSE from %d (%s)", msg->pid, process_get_peer_addr(msg->pid)->sun_path);

      // Forward response to process

      sendto(sock, buf, 256, 0, (struct sockaddr *)process_get_peer_addr(msg->pid), sizeof(struct sockaddr_un));
      
    }
    else if (msg->msg_id == READ) {

      emscripten_log(EM_LOG_CONSOLE, "READ from %d: %d %d", msg->pid, msg->_u.io_msg.fd, msg->_u.io_msg.len);

    }
    else if (msg->msg_id == WRITE) {

      emscripten_log(EM_LOG_CONSOLE, "WRITE from %d: %d %d", msg->pid, msg->_u.io_msg.fd, msg->_u.io_msg.len);

      unsigned char type;
      unsigned short major;
      int remote_fd;
      
      //TODO : read remaining bytes if needed

      msg->msg_id |= 0x80;

      // Get the fd of the process
      if (process_get_fd(msg->pid, msg->_u.ioctl_msg.fd, &type, &major, &remote_fd) >= 0) {

	if ( (major == vfs_major) && (vfs_write(remote_fd, msg->_u.io_msg.buf, msg->_u.io_msg.len) >= 0) ) {
	      
	  msg->_errno = 0;  
	}
	else {

	  msg->_errno = EBADF;
	}
      }
      else {

	msg->_errno = EBADF;
      }
      
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == IOCTL) {
      
      emscripten_log(EM_LOG_CONSOLE, "IOCTL from %d: %d %d", msg->pid, msg->_u.ioctl_msg.fd, msg->_u.ioctl_msg.op);

      unsigned char type;
      unsigned short major;
      int remote_fd;

      msg->msg_id |= 0x80;

      // Get the fd of the process
      if (process_get_fd(msg->pid, msg->_u.ioctl_msg.fd, &type, &major, &remote_fd) >= 0) {

	if ( (major == vfs_major) && (vfs_ioctl(remote_fd, msg->_u.ioctl_msg.op) >= 0) ) {
	      
	  msg->_errno = 0;  
	}
	else {

	  msg->_errno = EBADF;
	}
      }
      else {

	msg->_errno = EBADF;
      }

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == FCNTL) {
      
      emscripten_log(EM_LOG_CONSOLE, "FCNTL from %d: %d %d", msg->pid, msg->_u.fcntl_msg.fd, msg->_u.fcntl_msg.cmd);

    }
    else if (msg->msg_id == SETSID) {

      emscripten_log(EM_LOG_CONSOLE, "SETSID from %d", msg->pid);

      msg->_u.setsid_msg.sid = process_setsid(msg->pid);
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      if (msg->_u.setsid_msg.sid < 0)
	msg->_errno = EPERM;

      emscripten_log(EM_LOG_CONSOLE, "SETSID --> %d", msg->_u.setsid_msg.sid);

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
    }
    else if (msg->msg_id == GETSID) {

      emscripten_log(EM_LOG_CONSOLE, "GETSID from %d", msg->pid);

      if (msg->_u.getsid_msg.pid == 0)
	msg->_u.getsid_msg.sid = process_getsid(msg->pid);
      else
	msg->_u.getsid_msg.sid = process_getsid(msg->_u.getsid_msg.pid);

      //dump_processes();
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      if (msg->_u.getsid_msg.sid < 0)
	msg->_errno = EPERM;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
    }
    else if (msg->msg_id == FORK) {

      emscripten_log(EM_LOG_CONSOLE, "FORK from %d", msg->pid);

      msg->_u.fork_msg.child = process_fork(-1, msg->pid, NULL, NULL);
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      
    }
    else if (msg->msg_id == EXECVE) {

      emscripten_log(EM_LOG_CONSOLE, "EXECVE from %d: %lu", msg->pid, msg->_u.execve_msg.args_size);

      if (msg->_u.execve_msg.args_size == 0xffffffff) {

	if (msg->pid == ((struct message *)execve_msg)->pid) {

	  ((struct message *)execve_msg)->msg_id |= 0x80;

	  sendto(sock, execve_msg, execve_size, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	}
      }
      else {

	execve_size = bytes_rec;
	memcpy(execve_msg, msg, bytes_rec);
      }
    }
    else if (msg->msg_id == DUP) {

      emscripten_log(EM_LOG_CONSOLE, "DUP from %d", msg->pid);

      msg->_u.dup_msg.new_fd = process_dup(msg->pid, msg->_u.dup_msg.fd, msg->_u.dup_msg.new_fd);
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == GETPPID) {

      emscripten_log(EM_LOG_CONSOLE, "GETPPID from %d", msg->pid);

      msg->_u.getppid_msg.ppid = process_getppid(msg->pid);
      
      //dump_processes();
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr)); 
    }
    else if (msg->msg_id == GETPGID) {

      emscripten_log(EM_LOG_CONSOLE, "GETPPID from %d", msg->pid);

      if (msg->_u.getpgid_msg.pid == 0)
	msg->_u.getpgid_msg.pgid = process_getpgid(msg->pid);
      else
	msg->_u.getpgid_msg.pgid = process_getpgid(msg->_u.getsid_msg.pid);
      
      //dump_processes();
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr)); 
    }
    else if (msg->msg_id == SETPGID) {

      emscripten_log(EM_LOG_CONSOLE, "SETPPID from %d", msg->pid);

      if (msg->_u.getpgid_msg.pid == 0)
        process_setpgid(msg->pid, msg->_u.getpgid_msg.pgid);
      else
        process_setpgid(msg->_u.getpgid_msg.pid, msg->_u.getpgid_msg.pgid);
      
      //dump_processes();
      
      msg->msg_id |= 0x80;
      msg->_errno = 0;

      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr)); 
    }
  }
  
  return 0;
}
