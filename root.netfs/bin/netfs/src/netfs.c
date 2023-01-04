/*
 * Copyright (C) 2022 Benoit Baudaux
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

#define NETFS_VERSION "netfs v0.1.0"

#define NETFS_PATH "/tmp2/netfs.peer"
#define RESMGR_PATH "/tmp2/resmgr.peer"

#define NB_NETFS_MAX  16

struct device_ops {

  int (*open)(const char *pathname, int flags, mode_t mode);
  ssize_t (*read)(int fd, void *buf, size_t count);
  ssize_t (*write)(int fildes, const void *buf, size_t nbyte);
  int (*ioctl)(int fildes, int request, ... /* arg */);
  int (*close)(int fd);
};

static unsigned short major;
static unsigned short minor = 0;

static struct device_ops * devices[NB_NETFS_MAX];

static unsigned short fds[64];

static int netfs_open(const char * pathname, int flags, mode_t mode) {

  return 0;
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

int main() {

  int sock;
  struct sockaddr_un local_addr, resmgr_addr, remote_addr;
  int bytes_rec;
  socklen_t len;
  char buf[256];
  
  emscripten_log(EM_LOG_CONSOLE,"Starting " NETFS_VERSION "...");
  
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
  
  sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));

  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, &len);

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
      sprintf((char *)&msg->_u.dev_msg.dev_name[0], "tty%d", msg->_u.dev_msg.minor);
  
      sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
    }
    else if (msg->msg_id == (REGISTER_DEVICE|0x80)) {

      if (msg->_errno)
	continue;

      emscripten_log(EM_LOG_CONSOLE,"REGISTER_DEVICE successful: %d,%d,%d", msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor);
    }
    else if (msg->msg_id == OPEN) {

      int fd = get_device(msg->_u.open_msg.minor)->open((const char *)(msg->_u.open_msg.pathname), msg->_u.open_msg.flags, msg->_u.open_msg.mode);

      fds[fd] = minor;

      msg->_u.open_msg.fd = fd;

      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));     
      
    }
    else if (msg->msg_id == READ) {

      devices[fds[msg->_u.io_msg.fd]]->read(msg->_u.io_msg.fd, msg->_u.io_msg.buf, msg->_u.io_msg.len);
    }
    else if (msg->msg_id == WRITE) {
      
      devices[fds[msg->_u.io_msg.fd]]->write(msg->_u.io_msg.fd, msg->_u.io_msg.buf, msg->_u.io_msg.len);
    }
    else if (msg->msg_id == IOCTL) {

      
    }
    else if (msg->msg_id == CLOSE) {

      
    }
  }

  
  
  return 0;
}
