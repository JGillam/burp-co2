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

import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import com.professionallyevil.co2.Co2Configurable;
import com.professionallyevil.co2.Co2Extender;

import javax.swing.*;
import java.awt.*;

/**
 * Delegate for burp.BurpExtender.  All the functionality should be implemented in this class rather than
 * burp.BurpExtender
 */
public class SQLMapperCo2Extender implements IExtensionStateListener, Co2Extender {
    public static final String VERSION = "1.5.1";
    private IBurpExtenderCallbacks callbacks;

    public SQLMapperCo2Extender() {
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("SQLMapper");

        SQLMapper mapper = new SQLMapper(callbacks, this);
        callbacks.registerContextMenuFactory(mapper);


        callbacks.customizeUiComponent(mapper.getTabComponent());
        callbacks.addSuiteTab(mapper);

        callbacks.printOutput("SQLMapper Loaded.  Version: " + VERSION);

    }

    @Override
    public void extensionUnloaded() {

    }

    /**
     * Callback to select the specified configurable item's tab.
     *
     * @param configurable The configurable item for which a tab should be selected.
     * @param selectCO2Tab ignored in this implementation.
     */
    public void selectConfigurableTab(Co2Configurable configurable, boolean selectCO2Tab) {
        Component tabComponent = configurable.getTabComponent();
        if (tabComponent != null) {
            Container parent = tabComponent.getParent();
            if (parent instanceof JTabbedPane) {
                ((JTabbedPane) parent).setSelectedComponent(tabComponent);
            }
        }
    }
}