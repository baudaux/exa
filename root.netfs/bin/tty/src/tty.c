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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stropts.h>
#include <stdio.h>

#include "msg.h"

#include <emscripten.h>

#define TTY_VERSION "tty v0.1.0"

#define TTY_PATH "/tmp2/tty.peer"
#define RESMGR_PATH "/tmp2/resmgr.peer"

#define NB_TTY_MAX  16

struct device_ops {

  int (*open)(const char * pathname, int flags, mode_t mode, pid_t pid, unsigned short minor);
  ssize_t (*read)(int fd, void * buf, size_t count);
  ssize_t (*write)(int fildes, const void *buf, size_t nbyte);
  int (*ioctl)(int fildes, int request, ... /* arg */);
  int (*close)(int fd);
};

struct client {

  pid_t pid;
  unsigned short minor;
  int flags;
  unsigned short mode;
};

static unsigned short major;
static unsigned short minor = 0;

static struct device_ops * devices[NB_TTY_MAX];

static int last_fd = -1;

static struct client clients[64];

int add_client(int fd, pid_t pid, unsigned short minor, int flags, unsigned short mode) {

  clients[fd].pid = pid;
  clients[fd].minor = minor;
  clients[fd].flags = flags;
  clients[fd].mode = mode;

  return fd;
}

static int local_tty_open(const char * pathname, int flags, mode_t mode, pid_t pid, unsigned short minor) {

  emscripten_log(EM_LOG_CONSOLE,"local_tty_open");

  ++last_fd;

  add_client(last_fd, pid, minor, flags, mode);
  
  return last_fd;
}

static ssize_t local_tty_read(int fd, void * buf, size_t count) {

  return 0;
}

static ssize_t local_tty_write(int fd, const void * buf, size_t count) {

  EM_ASM({

      let msg = {};
      msg.type = 2;
      msg.data = UTF8ToString($0);
	  
      Module["term_channel"].port1.postMessage(msg);
	  
    }, buf, count);
  
  return count;
}

static int local_tty_ioctl(int fildes, int request, ... /* arg */) {

  return 0;
}

static int local_tty_close(int fd) {

  return 0;
}

static struct device_ops local_tty_ops = {

  .open = local_tty_open,
  .read = local_tty_read,
  .write = local_tty_write,
  .ioctl = local_tty_ioctl,
  .close = local_tty_close,
};

EM_JS(int, probe_terminal, (), {

    let ret = Asyncify.handleSleep(function (wakeUp) {
				   
	Module["term_channel"] = new MessageChannel();

	// Listen for messages on port1
	Module["term_channel"].port1.onmessage = (e) => {

	  console.log("Message from Terminal: "+JSON.stringify(e.data));

	  if (e.data.type == 0) {

	    let msg = {};
	      msg.type = 2;
	      msg.data = "[tty v0.1.0]\n\r";

	      Module["term_channel"].port1.postMessage(msg);
	    
	    wakeUp(0);
	  }
	};
	   
	// Transfer port2 to parent window

	let msg = { };
	msg.type = 0;
	 
	window.parent.postMessage(msg, '*', [Module["term_channel"].port2]);
      });

    return ret;
});

int register_device(unsigned short minor, struct device_ops * dev_ops) {

  devices[minor] = dev_ops;

  return 0;
}

struct device_ops * get_device(unsigned short minor) {

  return devices[minor];
}

struct device_ops * get_device_from_fd(int fd) {

  return devices[clients[fd].minor];
}

int main() {

  int sock;
  struct sockaddr_un local_addr, resmgr_addr, remote_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1256];
  
  // Use console.log as tty is not yet started
  emscripten_log(EM_LOG_CONSOLE,"Starting " TTY_VERSION "...");
  
  /* Create the server local socket */
  sock = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (sock < 0) {
    return -1;
  }

  /* Bind server socket to TTY_PATH */
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sun_family = AF_UNIX;
  strcpy(local_addr.sun_path, TTY_PATH);
  
  if (bind(sock, (struct sockaddr *) &local_addr, sizeof(struct sockaddr_un))) {
    
    return -1;
  }

  memset(&resmgr_addr, 0, sizeof(resmgr_addr));
  resmgr_addr.sun_family = AF_UNIX;
  strcpy(resmgr_addr.sun_path, RESMGR_PATH);

  struct message * msg = (struct message *)&buf[0];
  
  msg->msg_id = REGISTER_DRIVER;
  msg->_u.dev_msg.dev_type = CHR_DEV;
  
  memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
  
  strcpy((char *)&msg->_u.dev_msg.dev_name[0], "tty");
  
  sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));

  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, &len);

    //emscripten_log(EM_LOG_CONSOLE, "tty: recfrom: %d", bytes_rec);

    if (msg->msg_id == (REGISTER_DRIVER|0x80)) {

      if (msg->_errno)
	continue;

      major = msg->_u.dev_msg.major;

      emscripten_log(EM_LOG_CONSOLE, "REGISTER_DRIVER successful: major=%d", major);

      // Probe terminal
      if (probe_terminal() == 0) {

	minor += 1;
	
	register_device(minor, &local_tty_ops);

	// Terminal probed: minor = 1
	msg->msg_id = REGISTER_DEVICE;
	msg->_u.dev_msg.minor = minor;

	memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
	sprintf((char *)&msg->_u.dev_msg.dev_name[0], "tty%d", msg->_u.dev_msg.minor);
  
	sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
      }
    }
    else if (msg->msg_id == (REGISTER_DEVICE|0x80)) {

      if (msg->_errno)
	continue;

      emscripten_log(EM_LOG_CONSOLE,"REGISTER_DEVICE successful: %d,%d,%d", msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor);
    }
    else if (msg->msg_id == OPEN) {

      emscripten_log(EM_LOG_CONSOLE, "tty: OPEN from %d, %d", msg->pid, msg->_u.open_msg.minor);

      int fd = get_device(msg->_u.open_msg.minor)->open("", msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->pid, msg->_u.open_msg.minor);

      msg->_u.open_msg.fd = fd;

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));     
      
    }
    else if (msg->msg_id == READ) {

      emscripten_log(EM_LOG_CONSOLE, "tty: READ from %d", msg->pid);
      
    }
    else if (msg->msg_id == WRITE) {

      emscripten_log(EM_LOG_CONSOLE, "tty: WRITE from %d", msg->pid);

      if (msg->_u.io_msg.fd == -1) {

	get_device(1)->write(-1, msg->_u.io_msg.buf, msg->_u.io_msg.len);
      }
      else {
      
	get_device_from_fd(msg->_u.io_msg.fd)->write(-1, msg->_u.io_msg.buf, msg->_u.io_msg.len);
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == IOCTL) {

      emscripten_log(EM_LOG_CONSOLE, "tty: IOCTL from %d", msg->pid);

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == CLOSE) {

      emscripten_log(EM_LOG_CONSOLE, "tty: CLOSE from %d, %d", msg->pid, msg->_u.close_msg.fd);

      // very temporary
      clients[msg->_u.close_msg.fd].pid = -1;

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));     
      
    }
  }
  
  return 0;
}
