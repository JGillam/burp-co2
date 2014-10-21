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

import javax.swing.*;
import java.awt.*;

public class MiscTab extends JPanel implements Co2Configurable {

    IntruderPayloadProcessor payloadProcessor;
    MessageBeautifierFactory beautifierFactory;

    public MiscTab(IBurpExtenderCallbacks callbacks) {
        FlowLayout flow = new FlowLayout();
        flow.setAlignment(FlowLayout.LEFT);
        this.setLayout(flow);
        Box mainBox = Box.createVerticalBox();

        payloadProcessor = new IntruderPayloadProcessor();
        callbacks.registerIntruderPayloadProcessor(payloadProcessor);

        beautifierFactory = new MessageBeautifierFactory(callbacks);

        mainBox.add(beautifierFactory.getUiComponent());

        mainBox.add(payloadProcessor.getUiComponent());

        this.add(mainBox);
    }


    @Override
    public Component getTabComponent() {
        return this;
    }

    @Override
    public String getTabTitle() {
        return "Misc.";
    }

    @Override
    public String getTabCaption() {
        return getTabTitle();
    }

    @Override
    public Component getUiComponent() {
        return this;
    }
}
