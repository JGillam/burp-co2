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

import burp.IIntruderPayloadProcessor;

import java.awt.*;

public class IntruderPayloadProcessor implements Co2Configurable, IIntruderPayloadProcessor {

    IntruderPayloadForm settingsForm;
    private int TRANSFORM_NONE = 0;
    private int TRANSFORM_ASCII = 1;


    public IntruderPayloadProcessor() {
        settingsForm = new IntruderPayloadForm();
    }

    @Override
    public Component getTabComponent() {
        return settingsForm.getSettingsPanel();
    }

    @Override
    public String getTabTitle() {
        return getProcessorName();
    }

    @Override
    public String getProcessorName() {
        return "ASCII Payloads";
    }

    @Override
    public byte[] processPayload(byte[] currentPayload, byte[] originalPayload, byte[] baseValue) {
        if (!settingsForm.useDelimiter() && settingsForm.getTransformationType() == TRANSFORM_NONE) {
            return currentPayload;
        } else {

            String payloadString = new String(currentPayload);
            StringBuilder newPayload = new StringBuilder();

            for (char c : payloadString.toCharArray()) {
                if (settingsForm.getTransformationType() == TRANSFORM_ASCII) {
                    newPayload.append((int) c);
                }
                if (settingsForm.useDelimiter()) {
                    newPayload.append(settingsForm.getDelimiter());
                }
            }

            if (settingsForm.useDelimiter()) {  // remove the last delimiter
                newPayload.delete(newPayload.length() - settingsForm.getDelimiter().length(), newPayload.length());
            }

            return newPayload.toString().getBytes();

        }
    }
}
