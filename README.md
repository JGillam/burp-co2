#Latest Burp CO<sub>2</sub> Suite binary: [Download](https://github.com/JGillam/burp-co2/releases/latest)
CO<sub>2</sub> is a project for lightweight and useful enhancements to Portswigger's popular Burp Suite web penetration tool
through the standard Extender API. If you are looking for the binaries, you can find them in the BApp Store within Burp.
The latest standalone .jar versions are also available [here](https://drive.google.com/folderview?id=0B_0PMu9iUbMOWmdZQ3A0LWRNb28&usp=sharing#list).

CO<sub>2</sub> is comprised of both a suite of modules as well as standalone versions of some of these modules, either due to
popular request or while still in early development prior to being added to the suite. The objectives of all CO<sub>2</sub> modules
include:

   * Free and open source
   * Works on both Free and Pro versions of Burp (except where Free version limits functionality, e.g. Intruder rate limits)
   * Lightweight with respect to memory and CPU utilization
   * Avoid third party library dependencies
   * Help available (online help, examples, etc...)
   * See the Co2Modules wiki page for descriptions of each of the modules in CO<sub>2</sub>.

See [ReleaseNotes](https://github.com/JGillam/burp-co2/blob/wiki/ReleaseNotes.md) for details of each release.


If you are interested in contributing or playing with the code, check out the setup instructions below:

##IntelliJ IDEA Setup Instructions:

This project is best built under IntelliJ IDEA.  There are several modules
with dependencies on other modules.  Here are some key modules:

burp-api:   The source is not populated by default!  You must put the latest
            API source from Burp into this source folder before building any
            of the other modules.

co2-core:   This module contains core functionality that is used across all
            the CO2 modules.

co2-suite:  This is the full CO<sub>2</sub> suite module.  It basically depends on everything
            else.


Output jar files from making these Burp extensions is organized under:

    burp-co2/out/artifacts
