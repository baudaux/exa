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

  unsigned char dev_type; /* enum blk_or_chr */
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

struct message {

  unsigned char msg_id; /* enum message_id on 7 bits, for answer the most significant bit is set to 1 */

  int _errno;

  union {

    struct device_message dev_msg;
    struct bind_message bind_msg;
    struct open_message open_msg;
    struct io_message io_msg;
  } _u;
};

#endif // _MSG_H
