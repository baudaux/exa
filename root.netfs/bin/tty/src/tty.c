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
#include <stdlib.h>
#include <sys/sysmacros.h>

#include <sys/ioctl.h>
#include <termios.h>

#include "msg.h"

#include <emscripten.h>

#define TTY_VERSION "[tty v0.1.0]"

#define TTY_PATH "/var/tty.peer"
#define RESMGR_PATH "/var/resmgr.peer"

#define NB_TTY_MAX  16

#define TTY_BUF_SIZE 1024

struct device_ops {

  int (*open)(const char * pathname, int flags, mode_t mode, pid_t pid, unsigned short minor);
  ssize_t (*read)(int fd, void * buf, size_t len);
  ssize_t (*write)(int fd, const void * buf, size_t len);
  int (*ioctl)(int fd, int op, unsigned char * buf, size_t len);
  int (*close)(int fd);
  ssize_t (*enqueue)(int fd, void * buf, size_t len, struct message * reply_msg);
  int (*select)(pid_t pid, int remote_fd, int fd, int read_write, int start_stop, struct sockaddr_un * sock_addr);
};

struct pending_request {

  pid_t pid;
  int fd;
  size_t len;
  struct sockaddr_un client_addr;
};

struct select_pending_request {

  pid_t pid;
  int remote_fd;
  int fd;
  struct sockaddr_un client_addr;
};

struct device_desc {

  struct termios ctrl;
  struct device_ops * ops;
  struct winsize ws;

  unsigned char buf[TTY_BUF_SIZE]; // circular buffer
  unsigned long start;
  unsigned long end;

  struct pending_request read_pending;
  struct select_pending_request read_select_pending;

  int session;
  int pgrp;
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

  devices[minor].start = 0;
  devices[minor].end = 0;

  devices[minor].session = -1;
  devices[minor].pgrp = -1;

  return 0;
}

struct device_desc * get_device(unsigned short minor) {

  return &devices[minor];
}

struct device_desc * get_device_from_fd(int fd) {

  return &devices[clients[fd].minor];
}

EM_JS(int, probe_terminal, (), {

    let buf_size = 256;

    let buf = new Uint8Array(buf_size);
    
    buf[0] = 23; // PROBE_TTY

    let msg = {

       from: "/var/tty.peer",
       buf: buf,
       len: buf_size
    };

    let bc = Module.get_broadcast_channel("/dev/tty1");
    
    bc.postMessage(msg);
  });

EM_JS(int, write_terminal, (unsigned char * buf, unsigned long len), {

    let msg = {

       from: "/var/tty.peer",
       write: 1,
       buf: Module.HEAPU8.slice(buf, buf+len),
       len: len
    };

    let bc = Module.get_broadcast_channel("/dev/tty1");
    
    bc.postMessage(msg);

    return len;
  });

static int add_char(struct device_desc * dev, unsigned char c) {

  int end2 = (dev->end+1)%TTY_BUF_SIZE;

  if (end2 != dev->start) {
    
    dev->buf[dev->end] = c;
    dev->end = end2;

    return 0;
  }

  return -1;
}

static int del_char(struct device_desc * dev) {

  if (dev->end == dev->start) {

    return -1;
  }
  
  int end2 = ((dev->end-1)>=0)?dev->end-1:TTY_BUF_SIZE-1;

  if ( (dev->buf[end2] == '\r') || (dev->buf[end2] == '\n') ) {

    return -1;
  }
  
  dev->end = end2;
  
  return 0;
}

static void extract_chars(struct device_desc * dev, size_t len, unsigned char * buf) {

  int i;
  size_t n = 0;
  
  for (i = dev->start; n < len; i = (i+1)%TTY_BUF_SIZE) {

    buf[n] = dev->buf[i];
    ++n;
  }

  dev->start = i;
}

static int local_tty_open(const char * pathname, int flags, mode_t mode, pid_t pid, unsigned short minor) {

  //emscripten_log(EM_LOG_CONSOLE,"local_tty_open: %d", last_fd);

  ++last_fd;

  add_client(last_fd, pid, minor, flags, mode);
  
  return last_fd;
}

static ssize_t local_tty_read(int fd, void * buf, size_t len) {

  struct device_desc * dev = (fd == -1)?get_device(1):get_device_from_fd(fd);
  
  size_t len2 = 0;

  if (dev->ctrl.c_lflag & ICANON) {

    // Search EOL

    for (int i = dev->start; i != dev->end; i = (i+1)%TTY_BUF_SIZE) {

      if ( (dev->buf[i] == '\n') || (dev->buf[i] == '\r') ) {

	len2 = (i >= dev->start)?i-dev->start+1:TTY_BUF_SIZE-dev->start+i+1;
	break;
      }
    }
      
  }
  else {

    len2 = (dev->end >= dev->start)?dev->end-dev->start+1:TTY_BUF_SIZE-dev->start+dev->end+1;
  }

  if (len2 > 0) {
      
    size_t sent_len = (len2 <= len)?len2:len;

    extract_chars(dev, sent_len, buf);

    return sent_len;
  }
    
  return 0;
}

static ssize_t local_tty_write(int fd, const void * buf, size_t count) {

  unsigned char tmp_buf[4096];
  struct termios * ctrl = (fd == -1)?&(get_device(1)->ctrl):&(get_device_from_fd(fd)->ctrl);

  unsigned char * data = (unsigned char *)buf;

  //emscripten_log(EM_LOG_CONSOLE, "local_tty_write: count=%d %d", count, ctrl->c_oflag);

  int j = 0;

  for (int i = 0; i < count; ++i) {

    //emscripten_log(EM_LOG_CONSOLE, "local_tty_write: i=%d c=%d", i, ((unsigned char *)buf)[i]);

    if ( (data[i] == '\n') && (ctrl->c_oflag & ONLCR) ) {

      tmp_buf[j] = '\r';
      ++j;
      }
    else if ( (data[i] == '\r') && (ctrl->c_oflag & OCRNL) ) {

      tmp_buf[j] = '\n';
      ++j;
      continue;
      }
    else if ( (data[i] == '\r') && (ctrl->c_oflag & ONLRET) ) {

      continue;
      }
    
    tmp_buf[j] = data[i];
    ++j;
  }

  //emscripten_log(EM_LOG_CONSOLE, "local_tty_write: j=%d", j);

  write_terminal(tmp_buf, j);
  
  return count;
}

static int local_tty_ioctl(int fd, int op, unsigned char * buf, size_t len) {
  
  //emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: fd=%d op=%d", fd, op);
  
  switch(op) {

  case TIOCGWINSZ:
    
    memcpy(buf, &(get_device_from_fd(fd)->ws), sizeof(struct winsize));

    break;

  case TCGETS:

    //emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TCGETS");

    memcpy(buf, &(get_device_from_fd(fd)->ctrl), sizeof(struct termios));

    break;

  case TCSETS:
  case TCSETSW:
  case TCSETSF:

    //emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TCSETS");

    memcpy(&(get_device_from_fd(fd)->ctrl), buf, sizeof(struct termios));

    break;

  case TCFLSH:

    //emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TCFLSH");
    
    break;

  case TIOCGPGRP:

    //emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TIOCGPGRP");

    if (get_device_from_fd(fd)->pgrp < 0)
      return -1;

    memcpy(buf, &(get_device_from_fd(fd)->pgrp), sizeof(int));
    
    break;

  case TIOCSPGRP:

    //emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TIOCSPGRP");

    memcpy(&(get_device_from_fd(fd)->pgrp), buf, sizeof(int));

    break;

  case TIOCNOTTY:

    //emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TIOCNOTTY");

    break;

  case TIOCSCTTY:

    //emscripten_log(EM_LOG_CONSOLE,"local_tty_ioctl: TIOCSCTTY");

    break;

  default:
    break;
  }
  
  return 0;
}

static int local_tty_close(int fd) {

  return 0;
}

static ssize_t local_tty_enqueue(int fd, void * buf, size_t count, struct message * reply_msg) {

  struct device_desc * dev = (fd == -1)?get_device(1):get_device_from_fd(fd);

  unsigned char * data = (unsigned char *)buf;

  unsigned char echo_buf[1024];

  int j = 0;

  for (int i = 0; i < count; ++i) {

    if ( (data[i] == '\r') && (dev->ctrl.c_iflag & IGNCR) ) {
      // do nothing
    }
    if ( (data[i] == '\r') && (dev->ctrl.c_iflag & ICRNL) ) {

      data[j] = '\n';
      ++j;
    }
    else if ( (data[i] == '\n') && (dev->ctrl.c_iflag & INLCR) ) {

      data[j] = '\r';
      ++j;
    }
    else {

      data[j] = data[i];
      ++j;
    }
  }

  int k = 0;

  for (int i = 0; i < j; ++i) {
    
    if (data[i] == dev->ctrl.c_cc[VERASE]) {

      if ( (dev->ctrl.c_lflag & (ICANON | ECHOE)) == (ICANON | ECHOE)) {
	
	// erase previous char (if any)

	if (del_char(dev) >= 0) {

	  echo_buf[k++] = 27;
	  echo_buf[k++] = '[';
	  echo_buf[k++] = 'D';
	  echo_buf[k++] = 27;
	  echo_buf[k++] = '[';
	  echo_buf[k++] = 'K';
	}
      }
      else {

	// enqueue
	add_char(dev, data[i]);
      }
    
    }
    else if (data[i] == dev->ctrl.c_cc[VWERASE]) {

      if ( (dev->ctrl.c_lflag & (ICANON | ECHOE)) == (ICANON | ECHOE)) {

	// erase previous word

	
      }
      else {

	// enqueue
	add_char(dev, data[i]);
      }
    
    }
    else if (data[i] == dev->ctrl.c_cc[VKILL]) {

      if ( (dev->ctrl.c_lflag & (ICANON | ECHOK)) == (ICANON | ECHOK)) {

	// erase current line

	
      }
      else {

	// enqueue
	add_char(dev, data[i]);
      }
    
    }
    else {

      add_char(dev, data[i]);

      if (dev->ctrl.c_lflag & ECHO) {

	echo_buf[k] = data[i];
	++k;
      }
    }
  }

  // Echo
  if (k > 0) {
    
    local_tty_write(fd, echo_buf, k);
  }

  if (j > 0) { // data has been enqueued

    if ( (dev->read_pending.fd >= 0) && (dev->read_pending.len > 0) ) { // Pending read

      size_t len = 0;

      if (dev->ctrl.c_lflag & ICANON) {

	// Search EOL

	for (int i = dev->start; i != dev->end; i = (i+1)%TTY_BUF_SIZE) {

	  if ( (dev->buf[i] == '\n') || (dev->buf[i] == '\r') ) {

	    len = (i >= dev->start)?i-dev->start+1:TTY_BUF_SIZE-dev->start+i+1;
	    break;
	  }
	}
      
      }
      else {

	len = (dev->end >= dev->start)?dev->end-dev->start+1:TTY_BUF_SIZE-dev->start+dev->end+1;
      }

      if (len > 0) {

	reply_msg->msg_id = READ|0x80;
	reply_msg->pid = dev->read_pending.pid;
	reply_msg->_errno = 0;
	reply_msg->_u.io_msg.fd = dev->read_pending.fd;

	size_t sent_len = (len <= dev->read_pending.len)?len:dev->read_pending.len;
      
	reply_msg->_u.io_msg.len = sent_len;

	//emscripten_log(EM_LOG_CONSOLE, "(2) dev->read_pending.len=%d dev->start=%d len=%d sent_len=%d", dev->read_pending.len, dev->start, len, sent_len);
	
	extract_chars(dev, sent_len, reply_msg->_u.io_msg.buf);

	return sent_len;
      }
    }
    else if (dev->read_select_pending.fd >= 0) {

      //emscripten_log(EM_LOG_CONSOLE, "read_select_pending.fd >= 0");

      reply_msg->msg_id = SELECT|0x80;
      reply_msg->pid = dev->read_select_pending.pid;
      reply_msg->_errno = 0;
      reply_msg->_u.select_msg.remote_fd = dev->read_select_pending.remote_fd;
      reply_msg->_u.select_msg.fd = dev->read_select_pending.fd;
      reply_msg->_u.select_msg.read_write = 0; // read
    }
  }
  
  return 0;
}

static void add_read_select_pending_request(pid_t pid, int remote_fd, int fd, struct sockaddr_un * sock_addr) {

  struct device_desc * dev = get_device_from_fd(remote_fd);

  dev->read_select_pending.pid = pid;
  dev->read_select_pending.remote_fd = remote_fd;
  dev->read_select_pending.fd = fd;
  memcpy(&dev->read_select_pending.client_addr, sock_addr, sizeof(struct sockaddr_un));

  //emscripten_log(EM_LOG_CONSOLE, "add_read_select_pending_request: %s", dev->read_select_pending.client_addr.sun_path);
}

static void del_read_select_pending_request(pid_t pid, int remote_fd, int fd, struct sockaddr_un * sock_addr) {

  struct device_desc * dev = get_device_from_fd(remote_fd);

  dev->read_select_pending.remote_fd = -1;
  dev->read_select_pending.fd = -1;
}

static int local_tty_select(pid_t pid, int remote_fd, int fd, int read_write, int start_stop, struct sockaddr_un * sock_addr) {

  struct device_desc * dev = get_device_from_fd(remote_fd);

  if (start_stop) { // start

    if (read_write) { // write

      return 1; // write is always possible
    }
    else { // read

      if (dev->start != dev->end) { // input buffer contains char

	return 1;
      }
      else {

	add_read_select_pending_request(pid, remote_fd, fd, sock_addr);
      }
    }
  }
  else { // stop

    del_read_select_pending_request(pid, remote_fd, fd, sock_addr);
  }
  
  return 0;
}

static struct device_ops local_tty_ops = {

  .open = local_tty_open,
  .read = local_tty_read,
  .write = local_tty_write,
  .ioctl = local_tty_ioctl,
  .close = local_tty_close,
  .enqueue = local_tty_enqueue,
  .select = local_tty_select,
};

static void add_read_pending_request(pid_t pid, int fd, size_t len, struct sockaddr_un * sock_addr) {

  struct device_desc * dev = get_device_from_fd(fd);

  dev->read_pending.pid = pid;
  dev->read_pending.fd = fd;
  dev->read_pending.len = len;
  memcpy(&dev->read_pending.client_addr, sock_addr, sizeof(struct sockaddr_un));
}

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
      probe_terminal();
    }
    else if (msg->msg_id == (PROBE_TTY|0x80)) {

      emscripten_log(EM_LOG_CONSOLE, "PROBE_TTY successful: rows=%d cols=%d",msg->_u.probe_tty_msg.rows, msg->_u.probe_tty_msg.cols);

      minor += 1;

      get_device(1)->ws.ws_row = msg->_u.probe_tty_msg.rows;
      get_device(1)->ws.ws_col = msg->_u.probe_tty_msg.cols;
	
      register_device(minor, &local_tty_ops);

      local_tty_write(-1, TTY_VERSION, strlen(TTY_VERSION));

      // Terminal probed: minor = 1
      msg->msg_id = REGISTER_DEVICE;

      msg->_u.dev_msg.dev_type = CHR_DEV;
      msg->_u.dev_msg.major = major;
      msg->_u.dev_msg.minor = minor;

      memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
      sprintf((char *)&msg->_u.dev_msg.dev_name[0], "tty%d", msg->_u.dev_msg.minor);
  
      sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
    }
    else if (msg->msg_id == (READ_TTY)) {

      unsigned char reply_buf[1256];
      struct message * reply_msg = (struct message *)&reply_buf[0];
      
      reply_msg->msg_id = 0;

      get_device(1)->ops->enqueue(-1, msg->_u.read_tty_msg.buf, msg->_u.read_tty_msg.len, reply_msg);

      if (reply_msg->msg_id == (READ|0x80)) {

	struct device_desc * dev = get_device(1);

	dev->read_pending.len = 0; // unset read pending
	dev->read_pending.fd = -1;

	sendto(sock, reply_buf, 1256, 0, (struct sockaddr *) &dev->read_pending.client_addr, sizeof(dev->read_pending.client_addr));
      }
      else if (reply_msg->msg_id == (SELECT|0x80)) {

	struct device_desc * dev = get_device(1);

	//emscripten_log(EM_LOG_CONSOLE, "Reply to select: %s", dev->read_select_pending.client_addr.sun_path);

	dev->read_select_pending.fd = -1; // unset read select pending
	dev->read_select_pending.remote_fd = -1;

	sendto(sock, reply_buf, 256, 0, (struct sockaddr *) &dev->read_select_pending.client_addr, sizeof(dev->read_select_pending.client_addr));
      }
      
    }
    else if (msg->msg_id == (REGISTER_DEVICE|0x80)) {

      if (msg->_errno)
	continue;

      //emscripten_log(EM_LOG_CONSOLE, "REGISTER_DEVICE successful: %d,%d,%d", msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor);
    }
    else if (msg->msg_id == OPEN) {

      //emscripten_log(EM_LOG_CONSOLE, "tty: OPEN from %d, %d", msg->pid, msg->_u.open_msg.minor);

      int remote_fd = get_device(msg->_u.open_msg.minor)->ops->open("", msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->pid, msg->_u.open_msg.minor);

      //emscripten_log(EM_LOG_CONSOLE, "tty: OPEN -> %d", remote_fd);

      msg->_u.open_msg.remote_fd = remote_fd;

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));     
      
    }
    else if (msg->msg_id == READ) {

      //emscripten_log(EM_LOG_CONSOLE, "tty: READ from %d: %d", msg->pid, msg->_u.io_msg.len);

      int count = get_device_from_fd(msg->_u.io_msg.fd)->ops->read(msg->_u.io_msg.fd, msg->_u.io_msg.buf, msg->_u.io_msg.len);
      
      if ( (count > 0) || (msg->_u.io_msg.len == 0) ) {
	
	msg->_u.io_msg.len = count;

	msg->msg_id |= 0x80;
	sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
      else {

	add_read_pending_request(msg->pid, msg->_u.io_msg.fd, msg->_u.io_msg.len, &remote_addr);
      }
    }
    else if (msg->msg_id == WRITE) {

      //emscripten_log(EM_LOG_CONSOLE, "tty: WRITE from %d, length=%d", msg->pid, msg->_u.io_msg.len);

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

      //emscripten_log(EM_LOG_CONSOLE, "tty: IOCTL from %d: %d", msg->pid, msg->_u.ioctl_msg.op);

      msg->_errno = get_device_from_fd(msg->_u.ioctl_msg.fd)->ops->ioctl(msg->_u.ioctl_msg.fd, msg->_u.ioctl_msg.op, msg->_u.ioctl_msg.buf, msg->_u.ioctl_msg.len);

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == FCNTL) {

      //emscripten_log(EM_LOG_CONSOLE, "tty: FCNTL from %d", msg->pid);

      // TODO: go through resmgr

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == CLOSE) {

      //emscripten_log(EM_LOG_CONSOLE, "tty: CLOSE from %d, %d", msg->pid, msg->_u.close_msg.fd);

      // very temporary
      clients[msg->_u.close_msg.fd].pid = -1;

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));     
      
    }
    else if (msg->msg_id == STAT) {
      
      //emscripten_log(EM_LOG_CONSOLE, "tty: STAT from %d: %s", msg->pid, msg->_u.stat_msg.pathname_or_buf);

      char * tty = strrchr(msg->_u.stat_msg.pathname_or_buf, '/')+1;

      if (strncmp(tty, "tty", 3) == 0) {

	int min = atoi(tty+3);
	
	//emscripten_log(EM_LOG_CONSOLE, "tty: min=%d", min);

	struct stat stat_buf;

	stat_buf.st_dev = makedev(major, min);
	stat_buf.st_ino = (ino_t)&devices[min];

	//emscripten_log(EM_LOG_CONSOLE, "tty: STAT -> %d %lld", stat_buf.st_dev, stat_buf.st_ino);

	msg->_u.stat_msg.len = sizeof(struct stat);
	memcpy(msg->_u.stat_msg.pathname_or_buf, &stat_buf, sizeof(struct stat));

	msg->_errno = 0;
      }
      else {

	msg->_errno = -1;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == LSTAT) {
      
      emscripten_log(EM_LOG_CONSOLE, "tty: LSTAT from %d: %s", msg->pid, msg->_u.stat_msg.pathname_or_buf);

      char * tty = strrchr(msg->_u.stat_msg.pathname_or_buf, '/')+1;

      if (strncmp(tty, "tty", 3) == 0) {

	int min = atoi(tty+3);
	
	//emscripten_log(EM_LOG_CONSOLE, "tty: min=%d", min);

	struct stat stat_buf;

	stat_buf.st_dev = makedev(major, min);
	stat_buf.st_ino = (ino_t)&devices[min];
	stat_buf.st_mode = S_IFCHR;

	//emscripten_log(EM_LOG_CONSOLE, "tty: LSTAT -> %d %lld", stat_buf.st_dev, stat_buf.st_ino);
	
	msg->_u.stat_msg.len = sizeof(struct stat);
	memcpy(msg->_u.stat_msg.pathname_or_buf, &stat_buf, sizeof(struct stat));

	msg->_errno = 0;
      }
      else {

	msg->_errno = -1;
      }

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == FSTAT) {
      
      //emscripten_log(EM_LOG_CONSOLE, "tty: FSTAT from %d: %d -> minor=%d", msg->pid, msg->_u.fstat_msg.fd, clients[msg->_u.fstat_msg.fd].minor);

      struct stat stat_buf;

      int min = clients[msg->_u.fstat_msg.fd].minor;

      stat_buf.st_dev = makedev(major, min);
      stat_buf.st_ino = (ino_t)&devices[min];
      stat_buf.st_mode = S_IFCHR;

      //emscripten_log(EM_LOG_CONSOLE, "tty: FSTAT -> %d %lld", stat_buf.st_dev, stat_buf.st_ino);

      msg->_u.fstat_msg.len = sizeof(struct stat);
      memcpy(msg->_u.fstat_msg.buf, &stat_buf, sizeof(struct stat));

      msg->msg_id |= 0x80;

      msg->_errno = 0;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

    }
    else if (msg->msg_id == SELECT) {
      
      //emscripten_log(EM_LOG_CONSOLE, "tty: SELECT from %d: %d %d %d (%x)", msg->pid, msg->_u.select_msg.fd, msg->_u.select_msg.read_write, msg->_u.select_msg.start_stop, get_device_from_fd(msg->_u.select_msg.remote_fd)->ops->select);

      if (get_device_from_fd(msg->_u.select_msg.remote_fd)->ops->select(msg->pid, msg->_u.select_msg.remote_fd, msg->_u.select_msg.fd, msg->_u.select_msg.read_write, msg->_u.select_msg.start_stop, &remote_addr) > 0) {

	 msg->msg_id |= 0x80;

	 msg->_errno = 0;
	 sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
      }
    }
  }
  
  return 0;
}
