/*
 * Copyright (c) 2014 Jason Gillam
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.secureideas.co2;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Class to encapsulate a version.  For comparison purposes.
 */
public class Version {
    private int major;  // significant changes in framework, and structure
    private int minor;  // additional or significant change in module functionality
    private int patch;  // bug fix or minor feature enhancement
    private int build;  // the build number
    private String extra = "";
    private String readibleVersionString;
    private Pattern versionPattern = Pattern.compile("^(?<major>[0-9]+)\\.(?<minor>[0-9]+)\\.(?<patch>[0-9]+)(([\\. ])?(?<extra>[a-zA-Z0-9]+))?(\\.(?<build>[0-9]+))?");


    public Version(String version){
        Matcher m = versionPattern.matcher(version);
        if(m.matches()){
            major = Integer.parseInt(m.group("major"));
            minor = Integer.parseInt(m.group("minor"));
            patch = Integer.parseInt(m.group("patch"));
            extra = m.group("extra")==null?"":m.group("extra");
            build = m.group("build")==null?0:Integer.parseInt(m.group("build"));
        }

        StringBuilder buf = new StringBuilder();
        buf.append(major).append('.');
        buf.append(minor).append('.');
        buf.append(patch);
        if(!extra.isEmpty()){
            buf.append(extra);
        }
        if(build>0){
            buf.append(" (build ");
            buf.append(build);
            buf.append(")");
        }
        this.readibleVersionString = buf.toString();
    }

    public Version(String versionString, String buildString){
        this(versionString+"."+buildString);
    }

    /**
     * Check if this version is newer than another version.  Only compares major, minor, and patch version.
     * Does not check build or extra fields.
     * @param version the version object to compare this one to
     * @return true iff this version is newer than the specified version.
     */
    public boolean isNewerThan(Version version) {
        if(this.major > version.major){
            return true;
        } else if (this.major == version.major) {
            return this.minor > version.minor || (this.minor == version.minor && this.patch > version.patch);
        }
        return false;
    }

    public String toString(){
        return readibleVersionString;
    }

    public String getVersionString(){
        StringBuilder buf = new StringBuilder();
        buf.append(major).append('.');
        buf.append(minor).append('.');
        buf.append(patch);
        if(!extra.isEmpty()){
            buf.append('.');
            buf.append(extra);
        }
        if(build>0){
            buf.append('.');
        buf.append(build);
        }
        return buf.toString();
    }

    public static void main(String[] args) {
        Version v = new Version("1.2.3");
        Version v1 = new Version("1.2.3.a");
        Version v2 = new Version ("1.2.3 a");
        Version v3 = new Version ("1.2.3.99");
        Version v4 = new Version ("1.2.3.a.99");

        System.out.println(v.toString());
        System.out.println(v1.toString());
        System.out.println(v2.toString());
        System.out.println(v3.toString());
        System.out.println(v4.toString());

    }
}
