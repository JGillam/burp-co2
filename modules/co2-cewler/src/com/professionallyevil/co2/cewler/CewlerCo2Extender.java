package com.professionallyevil.co2.cewler;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import com.professionallyevil.co2.Co2Configurable;
import com.professionallyevil.co2.Co2Extender;

import javax.swing.*;
import java.awt.*;

public class CewlerCo2Extender implements IExtensionStateListener, Co2Extender {
    public static final String VERSION = "0.2.0 b";
    private IBurpExtenderCallbacks callbacks;

    public CewlerCo2Extender() {
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("CeWLer");

        CewlerTab cewler = new CewlerTab(this);

        callbacks.customizeUiComponent(cewler.getTabComponent());
        callbacks.addSuiteTab(cewler);

        callbacks.printOutput("CeWLer Loaded.  Version: " + VERSION);
        callbacks.printOutput("Based on CeWL by DigiNinja.");
    }

    @Override
    public void extensionUnloaded() {
    }

    /**
     * Callback to select the specified configurable item's tab.
     *
     * @param configurable The configurable item for which a tab should be selected.
     * @param selectCo2Tab ignored in this implementation.
     */
    public void selectConfigurableTab(Co2Configurable configurable, boolean selectCo2Tab) {
        Component tabComponent = configurable.getTabComponent();
        if (tabComponent != null) {
            Container parent = tabComponent.getParent();
            if (parent instanceof JTabbedPane) {
                ((JTabbedPane) parent).setSelectedComponent(tabComponent);
            }
        }
    }
}
