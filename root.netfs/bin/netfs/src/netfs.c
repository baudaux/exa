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
#include <errno.h>

#include "msg.h"

#include <emscripten.h>

#define NETFS_VERSION "netfs v0.1.0"

#define NETFS_PATH "/tmp2/netfs.peer"
#define RESMGR_PATH "/tmp2/resmgr.peer"

#define NB_NETFS_MAX  16

struct device_ops {

  int (*open)(const char *pathname, int flags, mode_t mode, pid_t pid, unsigned short minor);
  ssize_t (*read)(int fd, void *buf, size_t count);
  ssize_t (*write)(int fildes, const void *buf, size_t nbyte);
  int (*ioctl)(int fildes, int request, ... /* arg */);
  int (*close)(int fd);
};

struct fd_entry {

  pid_t pid;
  unsigned short minor;
  char pathname[1024];
  int flags;
  unsigned short mode;
};

static unsigned short major;
static unsigned short minor = 0;

static struct device_ops * devices[NB_NETFS_MAX];

static int last_fd = -1;

static struct fd_entry fds[64];

int add_fd_entry(int fd, pid_t pid, unsigned short minor, const char * pathname, int flags, unsigned short mode) {

  fds[fd].pid = pid;
  fds[fd].minor = minor;
  strcpy(fds[fd].pathname, pathname);
  fds[fd].flags = flags;
  fds[fd].mode = mode;
  
  return fd;
}

EM_JS(int, do_fetch_head, (const char * pathname), {
    
  return Asyncify.handleSleep(function (wakeUp) {

      var myHeaders = new Headers();

      var myInit = { method: 'HEAD',
	headers: myHeaders,
	mode: 'cors',
	cache: 'default' };
      
      fetch(UTF8ToString(pathname), myInit).then(function (response) {

	  if (response.ok)
	    wakeUp(0);
	  else
	    wakeUp(-1);
    });
  });
});

static int netfs_open(const char * pathname, int flags, mode_t mode, pid_t pid, unsigned short minor) {

  if (do_fetch_head(pathname) == 0) {

    ++last_fd;
    
    add_fd_entry(last_fd, pid, minor, pathname, flags, mode);
  
    return last_fd;
  }

  return -1;
}

static ssize_t netfs_read(int fd, void * buf, size_t count) {

  return 0;
}

static ssize_t netfs_write(int fd, const void * buf, size_t count) {

  
  return 0;
}

static int netfs_ioctl(int fildes, int request, ... /* arg */) {

  return 0;
}

static int netfs_close(int fd) {

  return 0;
}

static struct device_ops netfs_ops = {

  .open = netfs_open,
  .read = netfs_read,
  .write = netfs_write,
  .ioctl = netfs_ioctl,
  .close = netfs_close,
};

int register_device(unsigned short minor, struct device_ops * dev_ops) {

  devices[minor] = dev_ops;

  return 0;
}

struct device_ops * get_device(unsigned short minor) {

  return devices[minor];
}

struct device_ops * get_device_from_fd(int fd) {

  return devices[fds[fd].minor];
}

int main() {

  int sock;
  struct sockaddr_un local_addr, resmgr_addr, remote_addr;
  int bytes_rec;
  socklen_t len;
  char buf[1256];
  
  emscripten_log(EM_LOG_CONSOLE, "Starting " NETFS_VERSION "...");

  int fd = open("/dev/tty1", O_RDWR);
  
  if (fd >= 0)
    write(fd, "\n\r[" NETFS_VERSION "]", strlen("\n\r[" NETFS_VERSION "]")+1);
  
  /* Create the server local socket */
  sock = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (sock < 0) {
    return -1;
  }

  /* Bind server socket to NETFS_PATH */
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sun_family = AF_UNIX;
  strcpy(local_addr.sun_path, NETFS_PATH);
  
  if (bind(sock, (struct sockaddr *) &local_addr, sizeof(struct sockaddr_un))) {
    
    return -1;
  }

  memset(&resmgr_addr, 0, sizeof(resmgr_addr));
  resmgr_addr.sun_family = AF_UNIX;
  strcpy(resmgr_addr.sun_path, RESMGR_PATH);

  struct message * msg = (struct message *)&buf[0];
  
  msg->msg_id = REGISTER_DRIVER;
  msg->_u.dev_msg.dev_type = FS_DEV;
  
  memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
  
  strcpy((char *)&msg->_u.dev_msg.dev_name[0], "netfs");
  
  sendto(sock, buf, 1256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));

  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, &len);

    if (msg->msg_id == (REGISTER_DRIVER|0x80)) {

      if (msg->_errno)
	continue;

      major = msg->_u.dev_msg.major;

      emscripten_log(EM_LOG_CONSOLE,"REGISTER_DRIVER successful: major=%d",major);

      minor += 1;
	
      register_device(minor, &netfs_ops);
      
      msg->msg_id = REGISTER_DEVICE;
      msg->_u.dev_msg.minor = minor;

      memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
      sprintf((char *)&msg->_u.dev_msg.dev_name[0], "netfs%d", msg->_u.dev_msg.minor);
  
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
    }
    else if (msg->msg_id == (REGISTER_DEVICE|0x80)) {

      if (msg->_errno)
	continue;

      emscripten_log(EM_LOG_CONSOLE,"REGISTER_DEVICE successful: %d,%d,%d", msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor);

      unsigned short minor = msg->_u.dev_msg.minor;

      msg->msg_id = MOUNT;
      msg->_u.mount_msg.dev_type = FS_DEV;
      msg->_u.mount_msg.major = major;
      msg->_u.mount_msg.minor = minor;

      memset(msg->_u.mount_msg.pathname, 0, sizeof(msg->_u.mount_msg.pathname));
      strcpy((char *)&msg->_u.mount_msg.pathname[0], "/bin");
  
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
    }
    else if (msg->msg_id == OPEN) {

      int fd = get_device(msg->_u.open_msg.minor)->open((const char *)(msg->_u.open_msg.pathname), msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->pid, msg->_u.dev_msg.minor);

      if (fd >= 0) {

	msg->_u.open_msg.fd = fd;
	msg->_errno = 0;
      }
      else {

	msg->_u.open_msg.fd = -1;
	msg->_errno = ENOENT;
      }
	

      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));     
      
    }
    else if (msg->msg_id == READ) {

      //devices[fds[msg->_u.io_msg.fd]]->read(msg->_u.io_msg.fd, msg->_u.io_msg.buf, msg->_u.io_msg.len);
    }
    else if (msg->msg_id == WRITE) {
      
      //devices[fds[msg->_u.io_msg.fd]]->write(msg->_u.io_msg.fd, msg->_u.io_msg.buf, msg->_u.io_msg.len);
    }
    else if (msg->msg_id == IOCTL) {

      
    }
    else if (msg->msg_id == CLOSE) {

      
    }
  }

  
  
  return 0;
}