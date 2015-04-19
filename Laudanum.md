# Introduction #

The CO2 Laudanum module contains a set of Laudanum shell payloads that have been adapted to the Burp CO2 framework.  These are the types of file payloads that tend to work with vulnerabilities that allow files to be uploaded to the web root.  Details on the Laudanum project itself can be found at http://laudanum.professionallyevil.com.

The CO2 version of Laudanum works slightly differently from the classic Laudanum shells in that the client is running within the Burp extension instead of running as Javascript on a page.  The Burp versions of the Laudanum script files therefore behave more like web services than their classic counterparts.

# Payload Generation #

To use Burp CO2's Laudanum, first look at the File Inclusion Setup section of the tab.  Set the options as follows:

  * **Type**: Set to the type of files supported by your target server.
  * **Restrict IP**: This is a comma-delimited list of IP addresses for which the script will restrict access.  A 404 response will be returned for any IP address not on the list that attempts to access the payload, making it very difficult to detect through web scans.
  * **Token**: This token will be checked by the script as an access check, and will respond with status code 403 if your token does not match.  This helps prevent unauthorized use of your exploit payload should someone else discover it.  The _Gen New Token_ button can be used to generate a decently random token.

Once these options are set to your liking, press the _Generate File_ button.  You will be prompted for file name and location and then you can open the file in your favorite text editor to check out your handiwork before uploading it to the server.

# Interacting With Payloads #

Once your payload is on the server, you can move on to the _Console_ section.  This section of the tab will use your token from the _File Inclusion Setup_ but will ignore the other fields from that section.  Set up the method (GET/POST), Host, Port, and Resource (i.e. location of your payload file on the target server).  The _Prepend_ section is only for use with Classic ASP payloads (this is a temporary option until a better way is worked out).

Press the _re/Connect_ button when you are ready to start.  If everything went well you should get a prompt in the text area below this button.