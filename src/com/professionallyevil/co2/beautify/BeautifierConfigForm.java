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

package com.professionallyevil.co2.beautify;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

public class BeautifierConfigForm {
    private JCheckBox enableJavascriptBeautifierCheckBox;
    private JPanel mainPanel;
    private static String SETTING_EXTENSION_ENABLED = "co2.beautifier.enabled";
    private IBurpExtenderCallbacks callbacks;


    public BeautifierConfigForm(IBurpExtenderCallbacks burpExtenderCallbacks) {
        this.callbacks = burpExtenderCallbacks;

        String enabledSetting = callbacks.loadExtensionSetting(SETTING_EXTENSION_ENABLED);
        enableJavascriptBeautifierCheckBox.setSelected(enabledSetting==null || Boolean.parseBoolean(enabledSetting));

        enableJavascriptBeautifierCheckBox.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                callbacks.saveExtensionSetting(SETTING_EXTENSION_ENABLED, ""+enableJavascriptBeautifierCheckBox.isSelected());
            }
        });
    }

    public JPanel getMainPanel() {
        return mainPanel;
    }


    public boolean getBeautifierEnabled(){
        return enableJavascriptBeautifierCheckBox.isSelected();
    }
}
