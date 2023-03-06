<!doctype html>
<html lang="en-us">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EXtended mAchine</title>
    <meta name="description" content="A new machine running in your browser"/>
    <meta property="og:type" content="website" />
    <meta property="og:title" content="EXtended mAchine"/>
    <meta property="og:description" content="A new machine running in your web browser"/>
    <meta property="og:url" content="https://www.extendedmachine.com"/>
    <meta property="og:image" content="https://www.extendedmachine.com/apple-touch-icon-114x114.png"/>
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:site" content="@benoitbaudaux" />
    <meta name="twitter:title" content="EXtended mAchine" />
    <meta name="twitter:description" content="A new machine running in your web browser" />
    <meta name="twitter:image" content="https://www.extendedmachine.com/apple-touch-icon-114x114.png" />
    <link rel="icon" type="image/png" href="/favicon-16x16.png" sizes="16x16"/>
    <link rel="icon" type="image/png" href="/favicon-32x32.png" sizes="32x32"/>
    <link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96"/>
    <link rel="apple-touch-icon" sizes="57x57" href="/apple-touch-icon-57x57.png"/>
    <link rel="apple-touch-icon" sizes="72x72" href="/apple-touch-icon-72x72.png"/>
    <link rel="apple-touch-icon" sizes="114x114" href="/apple-touch-icon-114x114.png"/>
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon-180x180.png"/>
    <link rel="stylesheet" href="startup/xterm/xterm.css" />
    <script src="startup/xterm/xterm.js"></script>
    <script src="startup/xterm/xterm-addon-fit.js"></script>

    <style>

      html, body {
	  
          height: 100%;
          padding: 0;
          margin: 0;
      }

      body {

          display: flex;
          justify-content: center;
          align-items: center;
	  flex-direction: column;
	  justify-content: space-between;
      }

      .header {

	  height: 20px;
	  width: 100%;
	  display: flex;
	  flex-direction: row-reverse;
      }

      .header > a {

	  padding: 2px;
      }

      .footer {

	  height: 20px;
	  width: 100%;
	  display: flex;
      }

      .footer > span {

	  padding: 2px;
      }

      iframe {

          display: none;
      }

      .tty {

          position: relative;
	  width: 80%;
	  height: 90%;
      }

      .terminal {

          padding: 2px;
      }

      .xterm .xterm-viewport{
	  #background-color: initial!important;
      }

      a {

	  color: inherit;
	  text-decoration: none;
	  margin-right: 5px;
      }

      a:hover {
	  
	  color: lightblue;
      }

    </style>

  </head>
  <body>

    <div class="header">
      <a href="mailto:info@extendedmachine.com">Contact</a>
      <a href="doc/index.html" target="_blank">Documentation</a>
      <a href="https://github.com/baudaux/" target="_blank">GitHub</a>
    </div>

    <div class="tty"></div>

    <div class="footer">
      <span>EXtended mAchine, a GNU/EXA distribution</span>
    </div>

    <script>

      const randomNumber = Math.floor(Math.random() * 360);

      document.body.style.backgroundColor = `hsl(${randomNumber}, 100%, 70%)`;
      
    </script>

    <script src="startup/term.js"></script>
    <script src="startup/startup.js"></script>
    
  </body>
</html>

<?php

	$filename = "counter/counter.txt";

	$fp = fopen($filename, "a");

	while(!flock($fp, LOCK_EX)) {  // acquire an exclusive lock
	    // waiting to lock the file
	}

	
	fwrite($fp, date('Y-m-d H:i:s') . "\n");  // add local date
	fflush($fp);            		// flush output before releasing the lock
	flock($fp, LOCK_UN);    		// release the lock

	fclose($fp);
?>
