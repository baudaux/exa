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

#include <fcntl.h>
#include <errno.h>

#include "vfs.h"
#include "process.h"
#include "device.h"

#include "msg.h"

#include <emscripten.h>

/* Be careful when changing this path as it may be also used in javascript */

#define RESMGR_ROOT "/tmp2"
#define RESMGR_FILE "resmgr.peer"
#define RESMGR_PATH RESMGR_ROOT "/" RESMGR_FILE

#define STARTING_EXA "Starting EXA v0.1.0..."

int main() {

  int sock;
  struct sockaddr_un local_addr, remote_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1256];

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

      // Add device in /dev
      struct vnode * vnode = vfs_find_node("/dev");
      if (vnode)
	vfs_add_dev(vnode, (const char *) msg->_u.dev_msg.dev_name, msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor);

      msg->msg_id |= 0x80;
      msg->_errno = 0;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

      if ( (msg->_u.dev_msg.dev_type == CHR_DEV) && (msg->_u.dev_msg.major == 1) ) {  // First device is tty
	
	memset(buf,0,256);
	msg->msg_id = WRITE;
	msg->_u.io_msg.fd = 1;
	strcpy((char *)msg->_u.io_msg.buf,STARTING_EXA);
	msg->_u.io_msg.len = strlen(STARTING_EXA);

	sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

	create_netfs_process();
      }
      
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

      msg->msg_id |= 0x80;
      msg->_errno = 0;

      emscripten_log(EM_LOG_CONSOLE, "OPEN %x %x %s", msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->_u.open_msg.pathname);

      struct vnode * vnode = vfs_find_node((const char *)msg->_u.open_msg.pathname);
      if (vnode) {

	//emscripten_log(EM_LOG_CONSOLE, "vnode found: %s",vnode->name);

	if (vnode->type == VDEV) {

	  emscripten_log(EM_LOG_CONSOLE, "vnode is a device: %d %d %d",vnode->_u.dev.type, vnode->_u.dev.major, vnode->_u.dev.minor);

	  msg->_u.open_msg.fd = -1;
	  //TODO: msg->_u.open_msg.type = vnode->_u.dev.type;
	  msg->_u.open_msg.major = vnode->_u.dev.major;
	  msg->_u.open_msg.minor = vnode->_u.dev.minor;
	  strcpy((char *)msg->_u.open_msg.peer, device_get_driver(vnode->_u.dev.type, vnode->_u.dev.major)->peer);
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

	if (msg->_u.open_msg.flags & O_CREAT) {

	  // TODO
	}
      }
      
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    
  }
  
  return 0;
}
