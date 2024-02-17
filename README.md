# Latest Burp CO<sub>2</sub> Suite binary: [Download](https://github.com/JGillam/burp-co2/releases/latest)
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


## IntelliJ IDEA Setup Instructions

This project is optimized for development in IntelliJ IDEA and involves multiple modules with interdependencies. To set up and build the project effectively, follow these guidelines:

### Key Modules:

1. **burp-api**:
    - **Important**: This module requires the latest Burp API source code.
    - Before building other modules, populate the `burp-api` module's source folder with the latest API source from Burp Suite.

2. **co2-core**:
    - Contains core functionality used across all CO2 modules.

3. **co2-suite**:
    - Represents the complete CO2 suite, depending on all other modules.

4. **co2-cewler**:
    - A standalone version of the CO2 Cewler module.
    - 
5. **co2-sqlmapper**:
    - A standalone version of the CO2 SQLMapper module.

### Gradle Build:

- The project uses Gradle for building and managing dependencies. Ensure you have Gradle set up and configured properly.
- Run `./gradlew build` to build the entire project or individual modules.

### IntelliJ IDEA GUI Designer:

- The project uses IntelliJ IDEA's GUI Designer for some components. Ensure the GUI Designer is configured to generate Java source code.
- This setting is found under `File -> Settings -> Editor -> GUI Designer` in IntelliJ IDEA. Select `Generate GUI into: Java source code`.
- This configuration ensures that changes made via the GUI Designer are reflected in the Java source files, which are crucial for the Gradle build process.
- To rebuild the gui classes after changing forms, you can use the IntelliJ `Build -> Groovy Resources -> Build Resources` menu option. 

### Output Artifacts:

- Output JAR files from the build process are typically located in the `dist` directory of each module.
- The Gradle `fatJar` task consolidates dependencies into a single JAR file for each module.