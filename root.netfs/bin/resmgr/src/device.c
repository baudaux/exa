/*
 * Copyright (C) 2022 Benoit Baudaux
 */

#include <string.h>
#include <stdlib.h>

#include "device.h"
#include "msg.h"
#include "vfs.h"

#include <emscripten.h>

#define NB_DEV_MAX 16

struct driver {

  unsigned char type;
  unsigned short major;
  const char name[DEV_NAME_LENGTH_MAX];
  const char peer[108];
};

struct device {

  unsigned char type;
  unsigned short major;
  unsigned short minor;
  const char name[DEV_NAME_LENGTH_MAX];

  struct device * next;
};

static unsigned short majors[3];

static struct driver drivers[3][NB_DEV_MAX];
static struct device * devices;

static struct vnode * vfs_dev;

int add_driver(unsigned short major, unsigned char type, const char * name, const char * peer);

void device_init() {

  memset(majors, 0, sizeof(majors));
  memset(drivers, 0, sizeof(drivers));
  devices = NULL;

  struct vnode * vnode = vfs_find_node("/");

  // Add /dev
  vfs_dev = vfs_add_dir(vnode,"dev");

  // Add /tmp2 for early storage (socket path for example)
  vfs_add_dir(vnode,"tmp2");
}

unsigned short device_register_driver(unsigned char type, const char * name, const char * peer) {

  if (type > FS_DEV)
    return 0;

  if (majors[type] >= (NB_DEV_MAX-1))
    return 0;
  
  majors[type] += 1;
  
  int ret = add_driver(majors[type], type, name, peer);
  
  return majors[type];
}

int device_register_device(unsigned char type, unsigned short major, unsigned short minor, const char * name) {

  if ( (major == 0) || (drivers[type][major].major != major) )
    return -1;

  struct device * dev = (struct device *)malloc(sizeof(struct device));

  dev->type = type;
  dev->major = major;
  dev->minor = minor;
  strcpy((char *)dev->name, name);
  dev->next = NULL;

  if (devices == NULL) {

    devices = dev;
  }
  else {

    struct device * d = devices;

    while (d->next) {

      d = d->next;
    }

    d->next = dev;
  }
  
  return 0;
}

int add_driver(unsigned short major, unsigned char type, const char * name, const char * peer) {
  
  if (drivers[type][major].major != 0)
    return -1;

  drivers[type][major].major = major;
  drivers[type][major].type = type;
  strcpy((char *)drivers[type][major].name, name);
  strcpy((char *)drivers[type][major].peer, peer);
    
  return 0;
}
