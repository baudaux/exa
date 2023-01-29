/*
 * Copyright (C) 2022 Benoit Baudaux
 */


window.term = new Terminal({
    
});

const fitAddon = new FitAddon.FitAddon();
window.term.loadAddon(fitAddon);

window.term.open(document.getElementsByClassName('tty')[0]);
fitAddon.fit();

window.term.onData((data) => {

    if (window.term.driver_bc) {

	let uint8Array = [];

	for (let c of data)
	    uint8Array.push(c.charCodeAt(0));

	//window.term.encoder.encode(data);

	window.term.read_msg.buf.set(uint8Array, 16);

	window.term.read_msg.buf[12] = uint8Array.length & 0xff;
	window.term.read_msg.buf[13] = (uint8Array.length >> 8) & 0xff;
	window.term.read_msg.buf[14] = (uint8Array.length >> 16) & 0xff;
	window.term.read_msg.buf[15] = (uint8Array.length >> 24) & 0xff;
	
	window.term.driver_bc.postMessage(window.term.read_msg);
    }
});

window.term.bc = new BroadcastChannel("/dev/tty1");

window.term.read_buf = new Uint8Array(256);
window.term.read_buf[0] = 24;

window.term.read_msg = {

    from: "/dev/tty1",
    buf: window.term.read_buf,
    len: 256,
};

//window.term.encoder = new TextEncoder();

window.term.bc.onmessage = (messageEvent) => {

    let msg = messageEvent.data;

    if (msg.write) {
	
	window.term.write(msg.buf);
    }
    else if (msg.buf[0] == 23) {

	window.term.driver_bc = new BroadcastChannel(msg.from);

	msg.buf[0] |= 0x80;

	// rows
	msg.buf[12] = window.term.rows & 0xff;
	msg.buf[13] = (window.term.rows >> 8) & 0xff;

	// cols
	msg.buf[14] = window.term.cols & 0xff;
	msg.buf[15] = (window.term.cols >> 8) & 0xff;
	
	let msg2 = {

	    from: "/dev/tty1",
	    buf: msg.buf,
	    len: msg.buf.length
	};

	window.term.driver_bc.postMessage(msg2);
    }
};

window.term.focus();
