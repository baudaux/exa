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

#define RESMGR_ROOT "/tmp2"
#define RESMGR_FILE "resmgr.peer"
#define RESMGR_PATH RESMGR_ROOT "/" RESMGR_FILE

static char * starting_exa =  "\r\n"
"         __            __         \r\n"
"        /  \\----------/  \\        \r\n"
"        |                |        \r\n"
"        \\                /        \r\n"
"         \\              /         \r\n"
"          \\            /          \r\n"
"    _______|           |_______   \r\n"
"   /                           \\  \r\n"
"  |         EXA v0.1.0          | \r\n"
"   \\_______            ________/  \r\n"
"           /           \\          \r\n"
"	  /             \\          \r\n"
"	 /               \\         \r\n"
"	/      _____      \\        \r\n"
"       /      /     \\      \\      \r\n"
"      |      /       \\      |     \r\n"
"      \\_____/         \\_____/     \r\n"
  "\r\n";

int main() {

  int sock;
  struct sockaddr_un local_addr, remote_addr, tty_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1256];
  struct unordered_map * process_peer_map;

  // Use console.log as tty is not yet started
  emscripten_log(EM_LOG_CONSOLE, "Starting resmgr v0.1.0 ...");

  vfs_init();
  process_init();
  device_init();

  process_peer_map = new_unordered_map(-1, NULL);

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

  // First, we create tty process
  
  create_tty_process();
  
  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, &len);

    struct message * msg = (struct message *)&buf[0];

    emscripten_log(EM_LOG_CONSOLE, "resmgr: msg %d received from %s (%d)", msg->msg_id, remote_addr.sun_path,bytes_rec);

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

	if (strcmp((const char *)&(pathname[0]),"/bin") == 0) {

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

      msg->_u.socket_msg.fd = process_create_fd(msg->pid, -2, (unsigned char)msg->_u.socket_msg.type, (unsigned short)msg->_u.socket_msg.domain, (unsigned short)msg->_u.socket_msg.protocol);

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

      struct vnode * vnode = vfs_find_node((const char *)msg->_u.open_msg.pathname);
      if (vnode) {

	emscripten_log(EM_LOG_CONSOLE, "vnode found: %s",vnode->name);

	if (vnode->type == VDEV) {

	  emscripten_log(EM_LOG_CONSOLE, "vnode is a device: %d %d %d %s",vnode->_u.dev.type, vnode->_u.dev.major, vnode->_u.dev.minor, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);

	  // Forward msg to driver

	  void * item = malloc(sizeof(struct sockaddr_un));

	  memcpy(item, &remote_addr, sizeof(remote_addr));
	  
	  add_item_to_unordered_map(process_peer_map, msg->pid, item);
	  
	  msg->_u.open_msg.type = vnode->_u.dev.type;
	  msg->_u.open_msg.major = vnode->_u.dev.major;
	  msg->_u.open_msg.minor = vnode->_u.dev.minor;
	  strcpy((char *)msg->_u.open_msg.peer, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);

	  struct sockaddr_un driver_addr;

	  driver_addr.sun_family = AF_UNIX;
	  strcpy(driver_addr.sun_path, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);

	  sendto(sock, buf, 1256, 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));
	  
	}
	else if (vnode->type == VMOUNT) {

	  emscripten_log(EM_LOG_CONSOLE, "vnode is a mount point: %d %d %d",vnode->_u.dev.type, vnode->_u.dev.major, vnode->_u.dev.minor);

	  // TODO
	  
	}
	else if (vnode->type == VFILE) {

	  // TODO
	}
	else {

	  // TODO
	}
      }
      else {

	emscripten_log(EM_LOG_CONSOLE, "vnode not found");

	/*if (msg->_u.open_msg.flags & O_CREAT) {

	  // TODO
	}
	else*/ {

	  msg->msg_id |= 0x80;
	  msg->_errno = ENOENT;

	  sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	}
      }
    }
    else if (msg->msg_id == (OPEN|0x80)) {

      emscripten_log(EM_LOG_CONSOLE, "Response from OPEN from %d: %x %x %s %d %d", msg->pid, msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->_u.open_msg.pathname,msg->pid, msg->_u.open_msg.remote_fd);

      if (msg->_errno == 0) {

	msg->_u.open_msg.fd = process_create_fd(msg->pid, msg->_u.open_msg.remote_fd, msg->_u.open_msg.type, msg->_u.open_msg.major, msg->_u.open_msg.minor);
      }

      // Forward response to process

      struct unordered_map * item = get_item_from_unordered_map(process_peer_map, msg->pid);

      if (item) {

	sendto(sock, buf, 1256, 0, (struct sockaddr *)item->data, sizeof(struct sockaddr_un));

	remove_item_from_unordered_map(process_peer_map, item);
      }
      
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

	  void * item = malloc(sizeof(struct sockaddr_un));

	  memcpy(item, &remote_addr, sizeof(remote_addr));
	  
	  add_item_to_unordered_map(process_peer_map, msg->pid, item);

	  msg->_u.close_msg.fd = remote_fd;

	  struct sockaddr_un driver_addr;

	  driver_addr.sun_family = AF_UNIX;
	  strcpy(driver_addr.sun_path, device_get_driver(type, major)->peer);

	  sendto(sock, buf, 256, 0, (struct sockaddr *) &driver_addr, sizeof(driver_addr));
	}
	else {

	  // Other fd are there, do not close fd in the driver

	  msg->msg_id |= 0x80;
	  msg->_errno = 0;

	  sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	}
      }
      else {

	msg->msg_id |= 0x80;
	msg->_errno = EBADF;

	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
    }
    else if (msg->msg_id == (CLOSE|0x80)) {

      emscripten_log(EM_LOG_CONSOLE, "Response from CLOSE from %d", msg->pid);

      // Forward response to process

      struct unordered_map * item = get_item_from_unordered_map(process_peer_map, msg->pid);

      if (item) {

	sendto(sock, buf, 256, 0, (struct sockaddr *)item->data, sizeof(struct sockaddr_un));

	remove_item_from_unordered_map(process_peer_map, item);
      }
      
    }
  }
  
  return 0;
}
