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

import burp.*;
import com.secureideas.co2.beautify.Beautifier;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.Arrays;
import java.util.StringTokenizer;

public class MessageBeautifierFactory implements IMessageEditorTabFactory, Co2Configurable {
    IBurpExtenderCallbacks callbacks;
    BeautifierConfigForm tab = new BeautifierConfigForm();
    private boolean isEnabled = false;
    private static String SETTING_EXTENSION_ENABLED = "co2.beautifier.enabled";

    public MessageBeautifierFactory(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        String on = callbacks.loadExtensionSetting(SETTING_EXTENSION_ENABLED);
        if (on == null) {
            on = "true";
        }


        if( on!=null && Boolean.parseBoolean(on) ) {
            callbacks.registerMessageEditorTabFactory(this);
            isEnabled = true;
        }

        tab.getEnableJavascriptBeautifierCheckBox().addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                boolean enabled = tab.getEnableJavascriptBeautifierCheckBox().isSelected();
                if (enabled != isEnabled) {
                    MessageBeautifierFactory.this.callbacks.printOutput("Prettier Enabled changed to " + enabled);
                    isEnabled = enabled;
                    if (isEnabled) {
                        MessageBeautifierFactory.this.callbacks.registerMessageEditorTabFactory(MessageBeautifierFactory.this);
                    } else {
                        MessageBeautifierFactory.this.callbacks.removeMessageEditorTabFactory(MessageBeautifierFactory.this);

                    }
                    MessageBeautifierFactory.this.callbacks.saveExtensionSetting(SETTING_EXTENSION_ENABLED, "" + isEnabled);

                }

            }
        });

    }

    @Override
    public Component getTabComponent() {
        return tab.getMainPanel();
    }

    @Override
    public String getTabTitle() {
        return "Prettier JS";
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new Co2MessageBeautifier(controller, editable);
    }

    class Co2MessageBeautifier implements IMessageEditorTab {
        private boolean editable;
        private ITextEditor editor;
        private byte[] currentMessage;

        Co2MessageBeautifier(IMessageEditorController controller, boolean editable){
            this.editable = editable;
            editor = callbacks.createTextEditor();
            editor.setEditable(editable);
        }

        @Override
        public String getTabCaption() {
            return "Prettier";
        }

        @Override
        public Component getUiComponent() {
            return editor.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest) {
            if (!isRequest){
                IResponseInfo respinfo = callbacks.getHelpers().analyzeResponse(content);
                return ("script".equals(respinfo.getStatedMimeType()) || "script".equals(respinfo.getInferredMimeType()));
            } else{
                return false;
            }
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest) {
            if(content == null) {
                editor.setText(null);
                currentMessage = null;
            } else {
                int bodyOffset = callbacks.getHelpers().analyzeResponse(content).getBodyOffset();
                byte[] bodyContent = Arrays.copyOfRange(content, bodyOffset, content.length);

                currentMessage = content;
                editor.setText(beautifyJS(bodyContent));

            }
            editor.setEditable(false);
        }

        @Override
        public byte[] getMessage() {
            return currentMessage;
        }

        @Override
        public boolean isModified() {
            return false;
        }

        @Override
        public byte[] getSelectedData() {
            return editor.getSelectedText();
        }

        private byte[] beautifyJS(byte[] input) {
            Beautifier b = new Beautifier();
            String output = b.beautify(input);
            return output.getBytes();
        }
    }
}
