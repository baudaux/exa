#ifndef _MSG_H
#define _MSG_H

#define DEV_NAME_LENGTH_MAX  128

enum message_id {

  REGISTER_DRIVER = 1,
  UNREGISTER_DRIVER,
  REGISTER_DEVICE,
  UNREGISTER_DEVICE,
  MOUNT,
  UMOUNT,
  
  OPEN = 10,
  READ,
  WRITE,
  IOCTL,
  CLOSE
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

struct open_message {
  
  int flags;
  unsigned short mode;
  int fd;
  unsigned char pathname[1024];
};

struct write_message {
  
  unsigned long len;
  unsigned char buf[];
};

struct message {

  unsigned char msg_id; /* enum message_id on 7 bits, for answer the most significant bit is set to 1 */

  int errno;

  union {

    struct device_message dev_msg;
    struct open_message open_msg;
    struct write_message write_msg;
  } _u;
};

#endif // _MSG_H
