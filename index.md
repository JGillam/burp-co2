## Welcome Burp CO<sub>2</sub>
Burp CO<sub>2</sub> is an extension for the popular web proxy / web application testing tool called Burp Suite, available at [Portswigger](https://portswigger.net/). *You must install Burp Suite before installing the Burp CO<sub>2</sub> extension!*. The CO<sub>2</sub> extension includes a variety of functionality to enhance certain web penetration test tasks, such as an interface to make interacting with SQLMap more efficient and less error-prone, various tools for generating lists of users, a Laudanum exploitation shell implementation, and even a word masher for generating passwords.

## Suite Modules
### SQLMapper
The SQLMapper module provides an interface to the popular [SQLMap](http://sqlmap.org/) tool for discovering and exploiting SQL Injection flaws.  SQLMapper improves the efficiency of using SQLMap during a web penetration test.

### User Generator
This module uses name statistics to generate names or usernames. First name statistics are based on date ranges of common baby names. Last name statistics are based on census data.

### Name Mangler
Given a short list of first and last names, the name mangler will put them together in different orders and with different separation characters to generate a potential list of usernames.

### CeWLer
This tool is based on the popular [CeWL - Custom Word List](https://digi.ninja/projects/cewl.php) generator, by DigiNinja. Rather than re-crawling the site, this module pulls words from existing Burp history.

### Masher
Given a list of dictionary words and a password specification, Masher will begin generating potential passwords that can be used with Burp Intruder. This is a useful tool for generating a custom password dictionary for login forms that do not have effective lockout mechanisms.

### BasicAuther
Given a set of usernames and password this tool will generate a list of encoded payloads that can be submitted directly into the BASIC auth position of a request in Intruder.

## Burp CO2 Philosophy
With a background in software development, the author of Burp CO<sub>2</sub> (Jason Gillam), has designed each tool in the suite to work efficiently and in harmony with Burp Suite. The objectives of all CO<sub>2</sub> modules include:
* Free and open source
* Works on both Free and Pro versions of Burp (except where Free version limits functionality, e.g. Intruder rate limits)
* Lightweight with respect to memory and CPU utilization
* Avoid third party library dependencies
* Help available (online help, examples, etc...)