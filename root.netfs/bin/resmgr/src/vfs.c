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
#include <stdlib.h>

#include <emscripten.h>

#include "vfs.h"

static struct vnode * vfs_root;

int vfs_init() {

  vfs_root = NULL;

  vfs_root = vfs_add_dir(NULL, "/");
    
  return 0;
}

struct vnode * vfs_add_node(struct vnode * parent, enum vnode_type type, const char * name) {

  if (!parent && (type != VDIR))
    return NULL;

  if (parent && parent->type != VDIR)
    return NULL;
  
  struct vnode ** vnode_p = NULL;
  
  if (parent) {

    if (!parent->_u.link.vnode) {
      vnode_p = &parent->_u.link.vnode;
    }
    else {
      struct vnode * p = parent->_u.link.vnode;

      if (strcmp(p->name, name) == 0)
	return NULL;

      while (p->next) {

	p = p->next;

	if (strcmp(p->name, name) == 0)
	  return NULL;
      }

      vnode_p = &(p->next);
    }
  }

  struct vnode * n = (struct vnode *) malloc(sizeof(struct vnode));
  
  if (!n)
    return NULL;

  n->parent = parent;
  n->type = type;

  strcpy(n->name, name);
  
  n->next = NULL;

  if (vnode_p)
    *vnode_p = n;
  
  return n;
}

struct vnode * vfs_add_file(struct vnode * parent, const char * name) {

  struct vnode * vn = vfs_add_node(parent, VFILE, name);

  if (!vn)
    return NULL;

  vn->_u.file.buffer = NULL;
  vn->_u.file.buffer_size = 0;
  vn->_u.file.file_size = 0;

  return vn;
}

struct vnode * vfs_add_dir(struct vnode * parent, const char * name) {

  struct vnode * vn = vfs_add_node(parent, VDIR, name);

  if (!vn)
    return NULL;

  vn->_u.link.vnode = NULL;
  vn->_u.link.symlink = NULL;

  struct vnode * curr = vfs_add_symlink(vn, ".", ".", vn);

  struct vnode * n = (parent)?parent:vn;

  struct vnode * prev = vfs_add_symlink(vn, "..", "..", n);

  return vn;
}

struct vnode * vfs_add_symlink(struct vnode * parent, const char * name, const char * symlink, struct vnode * link) {

  struct vnode * vn = vfs_add_node(parent, VSYMLINK, name);

  if (!vn)
    return NULL;

  if (symlink)
    vn->_u.link.symlink = (unsigned char *) strdup(symlink);
  else {
    vn->_u.link.symlink = NULL;
  }

  vn->_u.link.vnode = link;

  return vn;
}

struct vnode * vfs_add_dev(struct vnode * parent, const char * name, unsigned char type, unsigned short major, unsigned short minor) {

  struct vnode * vn = vfs_add_node(parent, VDEV, name);

  if (!vn)
    return NULL;

  vn->_u.dev.type = type;
  vn->_u.dev.major = major;
  vn->_u.dev.minor = minor;

  return vn;
}

int vfs_set_mount(struct vnode * node, unsigned char type, unsigned short major, unsigned short minor) {

  node->type = VMOUNT;

  node->_u.dev.type = type;
  node->_u.dev.major = major;
  node->_u.dev.minor = minor;
    
  return 0;
}

struct vnode * vfs_add_path(const char * pathname) {

  //TODO
  return NULL;
}

struct vnode * vfs_find_node_in_subnodes(struct vnode * vnode, const char * pathname) {

  struct vnode * prev_node;
  const char * path = pathname;
  const char * path_end = pathname+strlen(pathname);

  //emscripten_log(EM_LOG_CONSOLE, "*** vfs_find_node_in_subnodes: %s (%d)", pathname,strlen(pathname));

  while (vnode) {
    
    //emscripten_log(EM_LOG_CONSOLE, "vfs_find_node_in_subnodes: %s (%d) == %s ?", vnode->name, strlen(vnode->name), path);

    if (strncmp(vnode->name, path, strlen(vnode->name)) == 0) {

      //emscripten_log(EM_LOG_CONSOLE, "vfs_find_node_in_subnodes: same name %d %d",strlen(path),strlen(vnode->name));

      if (strlen(path) == strlen(vnode->name)) {

	//emscripten_log(EM_LOG_CONSOLE, "vfs_find_node_in_subnodes: found");
	
	return vnode;
      }

      if ( (path[strlen(vnode->name)] == '/') || (strcmp(vnode->name, "/") == 0) ) {

	if (vnode->type == VDIR) {

	  path += strlen(vnode->name);
      
	  if (strcmp(vnode->name, "/"))
	    ++path;

	  struct vnode * vnode2 = vfs_find_node_in_subnodes(vnode->_u.link.vnode, path);

	  if (vnode2) {

	    //emscripten_log(EM_LOG_CONSOLE, "vfs_find_node_in_subnodes: found");
	    
	    return vnode2;
	  }
	}
	else if (vnode->type == VMOUNT) {

	  //emscripten_log(EM_LOG_CONSOLE, "vfs_find_node_in_subnodes: found dev");

	  return vnode;
	}
      }
    }
    
    vnode = vnode->next;
  }

  return NULL;
}

struct vnode * vfs_find_node(const char * pathname) {

  return vfs_find_node_in_subnodes(vfs_root, pathname);
}

struct vnode * vfs_create_file(const char * pathname) {

  //emscripten_log(EM_LOG_CONSOLE, "vfs_create_file: %s",pathname);
  
  // find path i.e last '/'
  char * p = strrchr(pathname,'/');

  if (!p)
    return NULL;

  //emscripten_log(EM_LOG_CONSOLE, "strrchr: %s",p);

  char * dir = (char *)malloc(p-pathname+1);

  if (!dir)
    return NULL;

  strncpy(dir,pathname,p-pathname);
  dir[p-pathname] = 0;

  //emscripten_log(EM_LOG_CONSOLE, "dir: %s",dir);

  // find path in vfs tree
  struct vnode * vnode = vfs_find_node(dir);

  //emscripten_log(EM_LOG_CONSOLE, "dir vnode: %p",vnode);
  
  if (!vnode || (vnode->type != VDIR)) {
    free(dir);
    return NULL;
  }

  //emscripten_log(EM_LOG_CONSOLE, "dir vnode: %s",vnode->name);

  // add file to path
  struct vnode * vfile = vfs_add_file(vnode,p+1);

  free(dir);
  
  return vfile;
}

void vfs_dump_node(struct vnode * vnode, int indent) {

  emscripten_log(EM_LOG_CONSOLE, "%*s * %s (%d)", (2*indent), "", vnode->name, vnode->type);

  if (vnode->type == VDIR) {
    struct vnode * link = vnode->_u.link.vnode;
  
    while (link) {

      vfs_dump_node(link,indent+1);

      link = link->next;
    }
  }
}

void vfs_dump() {

  emscripten_log(EM_LOG_CONSOLE, "VFS dump");
  
  vfs_dump_node(vfs_root,0);

  emscripten_log(EM_LOG_CONSOLE, "********");
}
