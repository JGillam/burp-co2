# Introduction #

This is a brief "how-to" guide for the SQLMapper module.  For starters, this module does not integrate with SQLMap.  You must have that installed separately.  What this module does is automagically construct a sqlmap command string given a request from Burp.


# To use SQLMapper: #

1. Simply right-click on any request to bring up the usual Burp popup-menu.  A new menu option should be available called "Send to SQLMapper (request)".  Selecting this will bring you over to the SQLMapper tab with your command pre-populated with reasonable defaults.

2. Use the configuration screen to select any additional options.  Note that this tool will not prevent you from selecting combinations of options that won't work.  Please read the sqlmap help (i.e. sqlmap --help) to better understand the options available.

3. Copy the command that's in the "SQLMap Command" box.  Right clicking this field will provide a menu action to do this quickly.

4. Note that the command does not actually start with sqlmap!  That's because different installations initiate sqlmap different ways (e.g. "sqlmap", "./sqlmap.py", "python sqlmap.py".  Type in that first part whichever way works for your setup, then paste the command you created in SQLMapper.