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

    let msg = {

	type: 1,
	data: data
    };

    window.term.postMessage(msg);
});

window.term.onMessage = (e) => {

    if (e.data.type == 2) {

	window.term.write(e.data.data);
    }
};

window.probe_term = function(e) {

    if (!window.term.postMessage) {

	window.term.postMessage = function(msg) {

	    e.ports[0].postMessage(msg);
	};

	e.ports[0].onmessage = window.term.onMessage;

	let msg = {

	    type: 0,
	    data: "Terminal probed"
	};

	window.term.postMessage(msg);

	return 0;
    }

    return -1;
};

window.term.focus();
