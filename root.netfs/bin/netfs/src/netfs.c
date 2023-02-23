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
#include <stdlib.h>

#include "msg.h"

#include <emscripten.h>

#define NETFS_VERSION "netfs v0.1.0"

#define NETFS_PATH "/var/netfs.peer"
#define RESMGR_PATH "/var/resmgr.peer"

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
  unsigned int size;
  unsigned int offset;
};

static unsigned short major;
static unsigned short minor = 0;

static struct device_ops * devices[NB_NETFS_MAX];

static int last_fd = 0;

static struct fd_entry fds[64];

int add_fd_entry(int fd, pid_t pid, unsigned short minor, const char * pathname, int flags, unsigned short mode, unsigned int size) {

  fds[fd].pid = pid;
  fds[fd].minor = minor;
  strcpy(fds[fd].pathname, pathname);
  fds[fd].flags = flags;
  fds[fd].mode = mode;
  fds[fd].size = size;
  fds[fd].offset = 0;
  
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
	  
	  //console.log(response.headers.get('Accept-Ranges'));
	  //console.log(response.headers.get('Content-Length'));

	  if (response.ok) {

	    let contentLength = 0;

	    if (typeof response.headers.get('Content-Length') == 'string') {
	      contentLength = parseInt(response.headers.get('Content-Length'));
	    }
	    
	    wakeUp(contentLength);
	  }
	  else
	    wakeUp(-1);
    });
  });
});

EM_JS(int, do_fetch, (const char * pathname, unsigned int offset, void * buf, unsigned int count), {
    
  return Asyncify.handleSleep(function (wakeUp) {

      var myHeaders = new Headers({'Range': 'bytes='+offset+'-'+(offset+count-1)});

      var myInit = { method: 'GET',
	headers: myHeaders,
	mode: 'cors',
	cache: 'default' };
      
      fetch(UTF8ToString(pathname), myInit).then(function (response) {
	  
	  //console.log(response.headers.get('Accept-Ranges'));
	  //console.log(response.headers.get('Content-Length'));

	  if (response.ok) {

	    let contentLength = 0;

	    if (typeof response.headers.get('Content-Length') == 'string') {
	      contentLength = parseInt(response.headers.get('Content-Length'));
	    }

	    /*response.arrayBuffer().then(buffer => {
		
		Module.HEAPU8.set(buffer, buf);
		
		wakeUp(contentLength);
		});*/

	    response.text().then(text => {

		//console.log(text);
		stringToUTF8(text, buf, count);
		
		//Module.HEAPU8.set(buffer, buf);
		
		wakeUp(contentLength);
		})
	    
	  }
	  else
	    wakeUp(-1);
    });
  });
});

static int netfs_open(const char * pathname, int flags, mode_t mode, pid_t pid, unsigned short minor) {

  emscripten_log(EM_LOG_CONSOLE,"netfs_open: %s", pathname);

  int size = do_fetch_head(pathname);
  
  if (size >= 0) {

    ++last_fd;
    
    add_fd_entry(last_fd, pid, minor, pathname, flags, mode, size);

    emscripten_log(EM_LOG_CONSOLE,"netfs_open -> %d %d %d %d %d", last_fd, pid, minor, size, fds[last_fd].offset);
  
    return last_fd;
  }

  return -1;
}

static ssize_t netfs_read(int fd, void * buf, size_t count) {

  emscripten_log(EM_LOG_CONSOLE,"netfs_read: %d %d %d %d", fd, count, fds[fd].offset, fds[fd].size);

  if (fds[fd].offset >= fds[fd].size) {

    return 0;
  }
  
  int size = do_fetch(fds[fd].pathname, fds[fd].offset, buf, count);

  emscripten_log(EM_LOG_CONSOLE,"netfs_read: %d bytes", size);

  if (size >= 0) {

    fds[fd].offset += size;

    return size;
  }
  
  return -1;
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

  int fd = open("/dev/tty1", O_WRONLY | O_NOCTTY);
  
  if (fd >= 0)
    write(fd, "\n\r[" NETFS_VERSION "]", strlen("\n\r[" NETFS_VERSION "]")+1);

  close(fd);
  
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

      emscripten_log(EM_LOG_CONSOLE, "REGISTER_DEVICE successful: %d,%d,%d", msg->_u.dev_msg.dev_type, msg->_u.dev_msg.major, msg->_u.dev_msg.minor);

      unsigned short minor = msg->_u.dev_msg.minor;

      msg->msg_id = MOUNT;
      msg->_u.mount_msg.dev_type = FS_DEV;
      msg->_u.mount_msg.major = major;
      msg->_u.mount_msg.minor = minor;

      memset(msg->_u.mount_msg.pathname, 0, sizeof(msg->_u.mount_msg.pathname));

      if (minor == 1)
	strcpy((char *)&msg->_u.mount_msg.pathname[0], "/bin");
      else if (minor == 2)
	strcpy((char *)&msg->_u.mount_msg.pathname[0], "/etc");
  
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
    }
    else if (msg->msg_id == (MOUNT|0x80)) {

      if (msg->_u.mount_msg.minor == 1) {
	
	minor += 1;
	
	register_device(minor, &netfs_ops);
      
	msg->msg_id = REGISTER_DEVICE;
	msg->_u.dev_msg.dev_type = FS_DEV;	
	msg->_u.dev_msg.major = major;
	msg->_u.dev_msg.minor = minor;

	memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
	sprintf((char *)&msg->_u.dev_msg.dev_name[0], "netfs%d", msg->_u.dev_msg.minor);
  
	sendto(sock, buf, 1256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
      }
    }
    
    else if (msg->msg_id == OPEN) {

      int remote_fd = get_device(msg->_u.open_msg.minor)->open((const char *)(msg->_u.open_msg.pathname), msg->_u.open_msg.flags, msg->_u.open_msg.mode, msg->pid, msg->_u.open_msg.minor);

      if (remote_fd >= 0) {

	msg->_u.open_msg.remote_fd = remote_fd;
	msg->_errno = 0;
      }
      else {

	msg->_u.open_msg.remote_fd = -1;
	msg->_errno = ENOENT;
      }
      
      msg->msg_id |= 0x80;
      sendto(sock, buf, 1256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == READ) {

      struct message * reply = (struct message *) malloc(sizeof(struct message)+msg->_u.io_msg.len);

      reply->msg_id = READ|0x80;
      reply->pid = msg->pid;
      reply->_u.io_msg.fd = msg->_u.io_msg.fd;
      
      struct device_ops * dev = get_device(fds[msg->_u.io_msg.fd].minor);

      if (dev) {
	
	reply->_u.io_msg.len = dev->read(msg->_u.io_msg.fd, reply->_u.io_msg.buf, msg->_u.io_msg.len);
	reply->_errno = 0;

	emscripten_log(EM_LOG_CONSOLE, "READ successful: %d bytes", reply->_u.io_msg.len);
      }
      else {

	emscripten_log(EM_LOG_CONSOLE, "READ error: %d %d", msg->_u.io_msg.fd, fds[msg->_u.io_msg.fd].minor);
	reply->_errno = ENXIO;
      }
      
      sendto(sock, reply, sizeof(struct message)+reply->_u.io_msg.len, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
    else if (msg->msg_id == WRITE) {
      
      
    }
    else if (msg->msg_id == IOCTL) {

      
    }
    else if (msg->msg_id == CLOSE) {

      msg->_errno = get_device(msg->_u.open_msg.minor)->close(msg->_u.close_msg.fd);
      msg->msg_id |= 0x80;
      sendto(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
    }
  }

  
  
  return 0;
}
