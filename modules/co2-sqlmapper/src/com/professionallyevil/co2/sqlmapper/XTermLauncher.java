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

package com.professionallyevil.co2.sqlmapper;

import java.util.ArrayList;
import java.util.List;

public class XTermLauncher extends SQLMapLauncher {

    @Override
    public boolean isOSMatch(String os) {
        return "Linux".equals(os);
    }

    @Override
    public List<String> getExecCommands(String sqlmapParams, String sqlmapPath) {
        List<String> commands = new ArrayList<String>();
        commands.add("xterm");
        commands.add("-e");
        commands.add("python " + sqlmapPath + " " + sqlmapParams);
        return commands;
    }

    @Override
    public String toString() {
        return "XTerm (Linux)";
    }
}
