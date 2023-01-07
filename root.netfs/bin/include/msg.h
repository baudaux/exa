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

#ifndef _MSG_H
#define _MSG_H

#include <sys/socket.h>
#include <sys/un.h>

#define DEV_NAME_LENGTH_MAX  128

enum message_id {

  REGISTER_DRIVER = 1,
  UNREGISTER_DRIVER,
  REGISTER_DEVICE,
  UNREGISTER_DEVICE,
  MOUNT,
  UMOUNT,
  
  BIND = 10,
  OPEN,
  READ,
  WRITE,
  IOCTL,
  CLOSE,
};

enum dev_type {

  BLK_DEV = 0,
  CHR_DEV,
  FS_DEV
};

struct device_message {

  unsigned char dev_type; /* enum dev_type */
  unsigned char dev_name[DEV_NAME_LENGTH_MAX];
  unsigned short major;
  unsigned short minor;
};

struct bind_message {
  
  struct sockaddr addr;
};

struct open_message {
  
  int fd;
  int flags;
  unsigned short mode;
  unsigned short major;
  unsigned short minor;
  unsigned char peer[108];
  unsigned char pathname[1024];
};

struct io_message {
  
  int fd;
  unsigned long len;
  unsigned char buf[];
};

struct mount_message {

  unsigned char dev_type;
  unsigned short major;
  unsigned short minor;
  char pathname[1024];
};

struct message {

  unsigned char msg_id; /* enum message_id on 7 bits, for answer the most significant bit is set to 1 */
  
  pid_t pid;

  int _errno;

  union {

    struct device_message dev_msg;
    struct bind_message bind_msg;
    struct open_message open_msg;
    struct io_message io_msg;
    struct mount_message mount_msg;
  } _u;
};

#endif // _MSG_H
