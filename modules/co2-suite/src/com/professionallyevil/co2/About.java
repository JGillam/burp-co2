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

import java.awt.*;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;


/**
 * This class handles the About tab logic.
 */
public class About implements Co2Configurable {

    AboutTab tab;
    String build;
    Version currentVersion;

    public About(IBurpExtenderCallbacks callbacks) {
        build = loadBuild();
        currentVersion = new Version(Co2SuiteExtender.VERSION, build);
        tab = new AboutTab(callbacks, currentVersion);
        ;
    }

    @Override
    public Component getTabComponent() {
        return tab.getMainPanel();
    }

    @Override
    public String getTabTitle() {
        return "About";
    }

    // NOTE: this always seems to come back one number behind - seems to be an issue with IntelliJ's build pre-processing order.
    private String loadBuild() {
        try {
            InputStream inStream = About.this.getClass().getClassLoader().getResourceAsStream("com/professionallyevil/co2/build.txt");
            Properties buildProps = new Properties();
            buildProps.load(inStream);
            inStream.close();
            return buildProps.getProperty("build.number");
        } catch (IOException e) {
            return "?";
        }


    }

    public void performUpdateCheck() {
        if (tab.isAutoCheck()) {
            tab.versionCheck(true);
        }
    }

    @Override
    public String getTabCaption() {
        return getTabTitle();
    }

    @Override
    public Component getUiComponent() {
        return getTabComponent();
    }
}
