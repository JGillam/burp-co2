# Introduction #

This page has a brief summary of each of the current CO<sub>2</sub> modules.  More detailed help is available on the professionally evil website: http://co2.professionallyevil.com/help.php.


# Modules #

  * [SQLMapper](SQLMapper.md) - send any request in Burp to this tool to get a SQLMap string you can paste to the command line.
  * UserGenerator - can be used to combine census (for surnames) and SSN (for first names) data to generate username lists that bubble names that statistically occur more frequently to the top of the list (e.g. “jsmith” would be the first item if you use just first initial, last name).  The tool has a number of options to generate different formats depending on what’s needed.
  * NameMangler - can be used to generate user names given some known users.  Useful when the username format is unknown.
  * CeWLer - a custom wordlist generator inspired by the legendary CeWL tool written by digininja (see http://www.digininja.org/projects/cewl.php)
  * Masher - given a word list and a password specification, Masher will generate an Intruder payload using permutations and variations of the words in the word list.
  * Prettier JS - a simplistic javascript beautifier.
  * ASCII Payload Processor - convert payloads into ascii decimal (don't laugh, I wrote this after encountering the need for it twice within a few month period in the wild!)


A note about OAuther: this module has been moved out of the Burp CO<sub>2</sub> project but is still available as a standalone Burp Extension here: http://extensions.professionallyevil.com/burp.php.