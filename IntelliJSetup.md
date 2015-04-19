# Introduction #

All the IntelliJ IDEA modules are defined but the project file is not, so you have to create it and then import each of the modules.  This is normally a one-time setup.

# Detailed Steps #

  1. Clone the repository.  Instructions are here: https://code.google.com/p/burp-co2/source/checkout
  1. Open a new project.  From the IntelliJ start page click "Open New Project".  The select the burp-co2 folder.  It will show up as an almost empty project in IntelliJ IDEA.
  1. Go into **Project Structure** and set the Project SDK
  1. Add each of the modules.  This can be done from the **File --> Import Module** menu.  Be sure to add all of them:
    * burp-api
    * co2-core
    * co2-laudanum
    * co2-sqlmapper
    * co2-suite

# Other Notes #
  * Artifacts (i.e. Jar files) for laudanum, sqlmapper, and co2suite should all be set up such that they will go to the burp-co2/out/artifacts directory when you do a build.
  * If a module won't import, try another one and come back to it.  The order shouldn't matter but sometimes it seems to anyway.