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

package com.professionallyevil.co2;

import burp.IBurpExtenderCallbacks;
import burp.ITab;

import javax.swing.*;
import java.awt.*;

/**
 * The main configuration tab for Co2 modules.  Each Co2Configurable module has its own subtab under this tab.
 */
public class Co2ConfigTab extends JPanel implements ITab {
    IBurpExtenderCallbacks callbacks;

    public Co2ConfigTab(IBurpExtenderCallbacks callbacks, Co2Configurable[] configurables) {
        super.setLayout(new GridLayout(1, 1));
        this.callbacks = callbacks;
        buildUI(configurables);
    }

    public void buildUI(Co2Configurable[] configurables) {
        JTabbedPane tabs = new JTabbedPane();
        for (Co2Configurable configurable : configurables) {
            tabs.add(configurable.getTabTitle(), configurable.getTabComponent());
        }

        Box mainBox = Box.createVerticalBox();
        mainBox.add(tabs);
        mainBox.add(Box.createVerticalGlue());
        this.add(mainBox);
    }

    @Override
    public String getTabCaption() {
        return "CO2";
    }

    @Override
    public Component getUiComponent() {
        return this;
    }
}
