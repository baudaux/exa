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

const iframe = document.createElement("iframe");
 
iframe.src = "/bin/resmgr/exa/exa.html";
iframe.setAttribute("pid", 1);

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

