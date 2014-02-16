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

// TODO: Currently not used.
public class Hunter implements Co2Configurable {
    HunterForm tab = new HunterForm();
    IBurpExtenderCallbacks callbacks;

    public Hunter(IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
        tab.setCallbacks(callbacks);
    }

    @Override
    public Component getTabComponent() {
        return tab.getMainPanel();
    }

    @Override
    public String getTabTitle() {
        return "Hunter";
    }
}
