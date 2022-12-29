/*
 * Copyright (C) 2022 Benoit Baudaux
 */

#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <stdio.h>

#include "msg.h"

#include <emscripten.h>

#define TTY_PATH "/tmp2/tty.peer"
#define RESMGR_PATH "/tmp2/resmgr.peer"

EM_JS(int, probe_terminal, (), {

    let ret = Asyncify.handleSleep(function (wakeUp) {
				   
	Module["term_channel"] = new MessageChannel();

	// Listen for messages on port1
	Module["term_channel"].port1.onmessage = (e) => {

	  console.log("Message from Terminal: "+JSON.stringify(e.data));

	  if (e.data.type == 0) {

	    /*let msg = {};
	      msg.type = 2;
	      msg.data = "Starting tty v0.1.0...";

	      Module["term_channel"].port1.postMessage(msg);*/
	    
	    wakeUp(0);
	  }
	};
	   
	// Transfer port2 to parent window

	let msg = { };
	msg.type = 0;
	 
	window.parent.postMessage(msg, '*', [Module["term_channel"].port2]);
      });

    return ret;
});

int main() {

  int sock;
  struct sockaddr_un local_addr, resmgr_addr, remote_addr;
  int bytes_rec;
  socklen_t len;
  char buf[256];
  unsigned short major;
  unsigned short minor = 0;
  
  unsigned int fds[64];
  
  // Use console.log as tty is not yet started
  emscripten_log(EM_LOG_CONSOLE,"Starting tty v0.1.0 ...");
  
  /* Create the server local socket */
  sock = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (sock < 0) {
    return -1;
  }

  /* Bind server socket to TTY_PATH */
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sun_family = AF_UNIX;
  strcpy(local_addr.sun_path, TTY_PATH);
  
  if (bind(sock, (struct sockaddr *) &local_addr, sizeof(struct sockaddr_un))) {
    
    return -1;
  }

  memset(&resmgr_addr, 0, sizeof(resmgr_addr));
  resmgr_addr.sun_family = AF_UNIX;
  strcpy(resmgr_addr.sun_path, RESMGR_PATH);

  struct message * msg = (struct message *)&buf[0];
  
  msg->msg_id = REGISTER_DRIVER;
  msg->_u.dev_msg.dev_type = CHR_DEV;
  
  memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
  
  strcpy((char *)&msg->_u.dev_msg.dev_name[0], "tty");
  
  sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));

  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, &len);

    if (msg->msg_id == (REGISTER_DRIVER|0x80)) {

      if (msg->errno)
	continue;

      major = msg->_u.dev_msg.major;

      emscripten_log(EM_LOG_CONSOLE,"REGISTER_DRIVER successful: major=%d",major);

      // Probe terminal
      if (probe_terminal() == 0) {

	// Terminal probed: minor = 1
	msg->msg_id = REGISTER_DEVICE;

	minor += 1;
	
	msg->_u.dev_msg.minor = minor;

	memset(msg->_u.dev_msg.dev_name, 0, sizeof(msg->_u.dev_msg.dev_name));
	sprintf((char *)&msg->_u.dev_msg.dev_name[0], "tty%d",msg->_u.dev_msg.minor);
  
	sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
      }
    }
    else if (msg->msg_id == (REGISTER_DEVICE|0x80)) {

      if (msg->errno)
	continue;

      emscripten_log(EM_LOG_CONSOLE,"REGISTER_DEVICE successful: %d,%d,%d",msg->_u.dev_msg.dev_type,msg->_u.dev_msg.major,msg->_u.dev_msg.minor);
    }
    else if (msg->msg_id == OPEN) {

      
    }
    else if (msg->msg_id == WRITE) {
      
      EM_ASM({

	  let msg = {};
	  msg.type = 2;
	  msg.data = UTF8ToString($0);
	  
	  Module["term_channel"].port1.postMessage(msg);
	  
	}, msg->_u.write_msg.buf, msg->_u.write_msg.len);
    }
  }

  
  
  return 0;
}
