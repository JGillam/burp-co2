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

/**
 * Class to encapsulate a version.  For comparison purposes.
 */
public class Version {
    private int major;  // significant changes in framework, and structure
    private int minor;  // additional or significant change in module functionality
    private int patch;  // bug fix or minor feature enhancement
    private int build;  // the build number
    private String extra = "";
    private String versionString;


    public Version(String version){
        String[] parts = version.split("\\.");
        if(parts.length > 0){
            major = Integer.parseInt(parts[0]);
        }
        if(parts.length > 1){
            minor = Integer.parseInt(parts[1]);
        }
        if(parts.length > 2){
            patch = Integer.parseInt(parts[2]);
        }

        if(parts.length > 4){
            build = Integer.parseInt(parts[4]);
            extra = parts[3];
        }else if(parts.length > 3){
            build = Integer.parseInt(parts[3]);
        }

        StringBuilder buf = new StringBuilder();
        buf.append(major);
        buf.append('.');
        buf.append(minor);
        buf.append('.');
        buf.append(patch);
        if(!extra.isEmpty()){
            buf.append(' ');
            buf.append(extra);
        }
        if(build>0){
            buf.append(" (build ");
            buf.append(build);
            buf.append(')');
        }
        this.versionString = buf.toString();
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
        return versionString;
    }

    public String getVersionString(){
        StringBuilder buf = new StringBuilder();
        buf.append(major).append('.');
        buf.append(minor).append('.');
        buf.append(patch).append('.');
        if(!extra.isEmpty()){
            buf.append(extra).append('.');
        }
        buf.append(build);
        return buf.toString();
    }
}
