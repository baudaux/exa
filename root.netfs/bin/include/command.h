#ifndef _MSG_H
#define _MSG_H

enum msg_id {

  REGISTER_DRIVER = 1,
  UNREGISTER_DRIVER,
  DRIVER_REGISTERED,
  REGISTER_DEVICE,
  UNREGISTER_DEVICE,
  DEVICE_REGISTERED,
};

struct driver_msg {

  unsigned char blk_or_chr;
  unsigned char name[];
};

struct device_msg {

};

struct msg {

  enum msg_id cmd_id;

  union {

    struct driver_msg drvmsg;
    struct device_msg devmsg;
  } _u;
};

#endif // _MSG_H
