<?php
// Voor zoekmachines:
header("HTTP/1.0 404 Not Found");

/*
  If a directory has no index page, IIS could do lots of different things:
  - it could show a 404 page
  - it could show a directory listing (!)
  - it could show a 403 page because unauthenticated users are not allowed to see directory listings
  - it could show a 500 page because something is wrong with the directory listing module
  - ... etc.

  So better to make certain we have an index.php so at least we know what will happen!
*/


/* If we keep the non-php part of this file very short, IE will replace it with its "own" generic 404 page,
   so it looks even more legit like there is absolutely nothing there... 
   OTOH, if you want to show a message, add a few lines of <-- comments --> it you want people to actually see it.
   */



?>
<h1>HTTP/1.0 404 Not Found</h1>
