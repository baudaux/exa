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

#include <sys/ioctl.h>
#include <termios.h>

#include "msg.h"

#include <emscripten.h>

#define TTY_VERSION "tty v0.1.0"

#define TTY_PATH "/var/tty.peer"
#define RESMGR_PATH "/var/resmgr.peer"

#define NB_TTY_MAX  16

struct device_ops {

  int (*open)(const char * pathname, int flags, mode_t mode, pid_t pid, unsigned short minor);
  ssize_t (*read)(int fd, void * buf, size_t count);
  ssize_t (*write)(int fd, const void * buf, size_t nbyte);
  int (*ioctl)(int fd, int op, unsigned char * buf, size_t len);
  int (*close)(int fd);
};

struct device_desc {

  struct termios ctrl;
  struct device_ops * ops;
};

struct client {

  pid_t pid;
  unsigned short minor;
  int flags;
  unsigned short mode;
};

static unsigned short major;
static unsigned short minor = 0;

static struct device_desc devices[NB_TTY_MAX];

static int last_fd = 0;

static struct client clients[64];

static unsigned char tmp_buf[4096];

int add_client(int fd, pid_t pid, unsigned short minor, int flags, unsigned short mode) {

  clients[fd].pid = pid;
  clients[fd].minor = minor;
  clients[fd].flags = flags;
  clients[fd].mode = mode;

  return fd;
}

void init_ctrl(struct termios * ctrl) {

  ctrl->c_iflag = ICRNL;
  ctrl->c_oflag = ONLCR;
  ctrl->c_cflag = 0;
  ctrl->c_lflag = TOSTOP | ECHOE | ECHO | ICANON | ISIG;

  ctrl->c_line = 0;

  ctrl->c_cc[VINTR] = 3;    // C-C
  ctrl->c_cc[VQUIT] = 28;   // C-backslash
  ctrl->c_cc[VERASE] = 127;
  ctrl->c_cc[VKILL] = 21;   // C-U
  ctrl->c_cc[VEOF] = 4;     // C-D
  ctrl->c_cc[VTIME] = 0;
  ctrl->c_cc[VMIN] = 1;
  ctrl->c_cc[VSWTC] = 0;
  ctrl->c_cc[VSTART] = 0;
  ctrl->c_cc[VSTOP] = 0;
  ctrl->c_cc[VSUSP] = 26;   // C-Z
  ctrl->c_cc[VEOL] = 0;
  ctrl->c_cc[VREPRINT] = 0;
  ctrl->c_cc[VDISCARD] = 0;
  ctrl->c_cc[VWERASE] = 23; // C-W
  ctrl->c_cc[VLNEXT] = 0;
  ctrl->c_cc[VEOL2] = 0;
  
  ctrl->__c_ispeed = B9600;
  ctrl->__c_ospeed = B9600;
}

int register_device(unsigned short minor, struct device_ops * dev_ops) {

  devices[minor].ops = dev_ops;

  init_ctrl(&devices[minor].ctrl);

  return 0;
}

struct device_desc * get_device(unsigned short minor) {

  return &devices[minor];
}

struct device_desc * get_device_from_fd(int fd) {

  return &devices[clients[fd].minor];
}

static int local_tty_open(const char * pathname, int flags, mode_t mode, pid_t pid, unsigned short minor) {

  emscripten_log(EM_LOG_CONSOLE,"local_tty_open: %d", last_fd);

  ++last_fd;

  add_client(last_fd, pid, minor, flags, mode);
  
  return last_fd;
}

static ssize_t local_tty_read(int fd, void * buf, size_t count) {

  return 0;
}

static ssize_t local_tty_write(int fd, const void * buf, size_t count) {
  
  struct termios * ctrl = (fd == -1)?&(get_device(1)->ctrl):&(get_device_from_fd(fd)->ctrl);

  //emscripten_log(EM_LOG_CONSOLE, "local_tty_write: count=%d %d", count, ctrl->c_oflag);

  int j = 0;

  for (int i = 0; i < count; ++i) {

    //emscripten_log(EM_LOG_CONSOLE, "local_tty_write: i=%d c=%d", i, ((unsigned char *)buf)[i]);

    if ( (((unsigned char *)buf)[i] == '\n') && (ctrl->c_oflag & ONLCR) ) {

      tmp_buf[j] = '\r';
      ++j;
      }
    
    tmp_buf[j] = ((unsigned char *)buf)[i];
    ++j;
  }

  //emscripten_log(EM_LOG_CONSOLE, "local_tty_write: j=%d", j);
  
  EM_ASM({

      let msg = {};
      msg.type = 2;
      msg.data = Module.HEAPU8.slice($0,$0+$1);
	  
      Module["term_channel"].port1.postMessage(msg);
	  
    }, tmp_buf, j);
  
  return count;
}

static int local_tty_ioctl(int fd, int op, unsigned char * buf, size_t len) {
  
  emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: fd=%d op=%d", fd, op);
  
  switch(op) {

  case TIOCGWINSZ:

    EM_ASM({

	Module.HEAPU8[$0] = Module["term_channel"].rows & 0xff;
	Module.HEAPU8[$0+1] = (Module["term_channel"].rows >> 8) & 0xff;
	Module.HEAPU8[$0+2] = Module["term_channel"].cols & 0xff;
	Module.HEAPU8[$0+3] = (Module["term_channel"].cols >> 8) & 0xff;
	  
    }, buf, len);

    break;

  case TCGETS:

    emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TCGETS");

    memcpy(buf, &(get_device_from_fd(fd)->ctrl), sizeof(struct termios));

    break;

  case TCSETS:
  case TCSETSW:
  case TCSETSF:

    emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TCSETS");

    memcpy(&(get_device_from_fd(fd)->ctrl), buf, sizeof(struct termios));

    break;

  default:
    break;
  }
  
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

	    Module["term_channel"].rows = e.data.rows;
	    Module["term_channel"].cols = e.data.cols;

	    let msg = {};
	      msg.type = 2;
	      msg.data = "[tty v0.1.0]";

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

int main() {

  int sock;
  struct sockaddr_un local_addr, resmgr_addr, remote_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1256];
  
  // Use console.log as tty is not yet started
  emscripten_log(EM_LOG_CONSOLE, "Starting " TTY_VERSION "...");
  
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

      int remote_fd = get_device(msg->_u.open_msg.minor)->ops->open("", msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->pid, msg->_u.open_msg.minor);

      emscripten_log(EM_LOG_CONSOLE, "tty: OPEN -> %d", remote_fd);

      msg->_u.open_msg.remote_fd = remote_fd;

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));     
      
    }
    else if (msg->msg_id == READ) {

      emscripten_log(EM_LOG_CONSOLE, "tty: READ from %d", msg->pid);
      
    }
    else if (msg->msg_id == WRITE) {

      emscripten_log(EM_LOG_CONSOLE, "tty: WRITE from %d, length=%d", msg->pid, msg->_u.io_msg.len);

      if (msg->_u.io_msg.fd == -1) {

	get_device(1)->ops->write(-1, msg->_u.io_msg.buf, msg->_u.io_msg.len);
      }
      else {
      
	get_device_from_fd(msg->_u.io_msg.fd)->ops->write(msg->_u.io_msg.fd, msg->_u.io_msg.buf, msg->_u.io_msg.len);
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == IOCTL) {

      emscripten_log(EM_LOG_CONSOLE, "tty: IOCTL from %d: %d", msg->pid, msg->_u.ioctl_msg.op);

      msg->_errno = get_device_from_fd(msg->_u.ioctl_msg.fd)->ops->ioctl(msg->_u.ioctl_msg.fd, msg->_u.ioctl_msg.op, msg->_u.ioctl_msg.buf, msg->_u.ioctl_msg.len);

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == FCNTL) {

      emscripten_log(EM_LOG_CONSOLE, "tty: FCNTL from %d", msg->pid);

      // TODO: go through resmgr

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
