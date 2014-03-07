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

import burp.*;
import com.professionallyevil.co2.beautify.Beautifier;
import java.awt.*;
import java.util.Arrays;

/**
 * Class to hook into Javascript beautifier tab
 */
public class MessageBeautifierFactory implements IMessageEditorTabFactory, Co2Configurable {
    IBurpExtenderCallbacks callbacks;
    BeautifierConfigForm tab;

    public MessageBeautifierFactory(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        tab = new BeautifierConfigForm(callbacks);
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
        return new Co2MessageBeautifier(editable);
    }

    class Co2MessageBeautifier implements IMessageEditorTab {
        private ITextEditor editor;
        private byte[] currentMessage;

        Co2MessageBeautifier(boolean editable){
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
            if (!isRequest && tab.getBeautifierEnabled()){
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
