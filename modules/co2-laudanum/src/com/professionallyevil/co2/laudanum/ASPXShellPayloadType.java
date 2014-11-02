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

package com.professionallyevil.co2.laudanum;

import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;

public class ASPXShellPayloadType extends PayloadType {

    @Override
    public void savePayload(Component parentComponent, String acceptIPs, String acceptToken) throws Exception {
        File file = chooseFile(parentComponent, "shell.aspx", "Choose aspx filename");
        if (file != null) {
            FileOutputStream fos = new FileOutputStream(file);
            processTemplate(fos, renderList(acceptIPs.split(","), ",", "\""), acceptToken);
        }
    }

    @Override
    String getTemplate() {
        return "com/professionallyevil/co2/laudanum/aspx/shell.aspx";
    }
}
