/*
 * Copyright (C) 2022 Benoit Baudaux
 */

#ifndef _VFS_H
#define _VFS_H

#include <stdio.h>

enum vnode_type {

  VDIR = 0,
  VFILE,
  VSYMLINK,
  VDEV
};

struct vnode {
  
  struct vnode * parent;
  
  enum vnode_type type;
  char name[FILENAME_MAX];
  
  union {
    struct {
      struct vnode * vnode;
      unsigned char * symlink;
    } link;
    struct {
      unsigned char * buffer;
      size_t buffer_size;
      size_t file_size;
    } file;
    struct {
      unsigned char type;
      unsigned short major;
      unsigned short minor;
    } dev;
  } _u;
  
  struct vnode * next;
};

int vfs_init();

struct vnode * vfs_add_node(struct vnode * parent, enum vnode_type type, const char * name);

struct vnode * vfs_add_file(struct vnode * parent, const char * name);
struct vnode * vfs_add_dir(struct vnode * parent, const char * name);
struct vnode * vfs_add_symlink(struct vnode * parent, const char * name, const char * symlink, struct vnode * link);
struct vnode * vfs_add_dev(struct vnode * parent, const char * name, unsigned char type, unsigned short major, unsigned short minor);

struct vnode * vfs_add_path(const char * pathname);

struct vnode * vfs_find_node(const char * pathname);

void vfs_dump();


#endif // _VFS_H
