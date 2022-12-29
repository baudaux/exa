/*
 * Copyright (C) 2022 Benoit Baudaux
 */

const iframe = document.createElement("iframe");
 
iframe.src = "/bin/resmgr/exa/exa.html";

document.body.appendChild(iframe);

window.addEventListener('message', (event) => {

    if (event.data.type == 3) { // fork from resmgr

	const iframe = document.createElement("iframe");
 
        iframe.setAttribute("pid", event.data.pid);
        iframe.setAttribute("name", "child");
        
        iframe.src = event.source.frameElement.src;
	
        document.body.appendChild(iframe);
    }
    else if (event.data.type == 0) {

	console.log("Probe terminal");

	if (window.probe_term) {

	    window.probe_term(event);
	}
    }
});

