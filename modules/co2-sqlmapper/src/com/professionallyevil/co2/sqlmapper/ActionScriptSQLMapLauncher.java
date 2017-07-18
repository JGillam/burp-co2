/*
 * Copyright (c) 2016 Jason Gillam
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

public class ActionScriptSQLMapLauncher extends SQLMapLauncher {

    @Override
    public boolean isOSMatch(String os) {
        return "Mac OS X".equals(os);
    }

    @Override
    public List<String> getExecCommands(String sqlmapParams, String sqlmapPath) {
        return getExecCommands(sqlmapParams, sqlmapPath, "python");
    }

    @Override
    public List<String> getExecCommands(String sqlmapParams, String sqlmapPath, String pythonPath) {
        List<String> commands = new ArrayList<String>();
        commands.add("osascript");
        commands.add("-e");
        sqlmapPath = sqlmapPath.replace("\\", "\\\\");
        sqlmapPath = sqlmapPath.replace("\"", "\\\"");
        commands.add("tell application \"Terminal\" \n\tactivate\n\tdo script \"" + pythonPath + " " + sqlmapPath + " " + sqlmapParams + "\"\nend tell");
        return commands;
    }

    @Override
    public String toString() {
        return "ActionScript (OSX)";
    }
}
