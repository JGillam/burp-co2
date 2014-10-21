Setup Instructions:

This project is best built under IntelliJ IDEA.  There are several modules
with dependencies on other modules.  Here are some key modules:

burp-api:   The source is not populated by default!  You must put the latest
            API source from Burp into this source folder before building any
            of the other modules.

co2-core:   This module contains core functionality that is used across all
            the CO2 modules.

co2-suite:  This is the full CO2 suite module.  It basically depends on everything
            else.


Output jar files from making these Burp extensions is organized under:

    burp-co2/out/artifacts