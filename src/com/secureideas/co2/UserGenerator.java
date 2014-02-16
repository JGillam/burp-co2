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

import burp.IBurpExtenderCallbacks;

import java.awt.*;

public class UserGenerator implements Co2Configurable {
    UserGeneratorForm form = new UserGeneratorForm();

    public UserGenerator(IBurpExtenderCallbacks callbacks){
        form.setCallbacks(callbacks);
    }

    @Override
    public Component getTabComponent() {
        return form.getMainPanel();
    }

    @Override
    public String getTabTitle() {
        return "User Generator";
    }
}
