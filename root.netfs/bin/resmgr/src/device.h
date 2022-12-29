/*
 * Copyright (C) 2022 Benoit Baudaux
 */

#ifndef _DEVICE_H
#define _DEVICE_H

void device_init();

unsigned short device_register_driver(unsigned char type, const char * name, const char * peer);

int device_register_device(unsigned char type, unsigned short major, unsigned short minor, const char * name);

#endif // _DEVICE_H
