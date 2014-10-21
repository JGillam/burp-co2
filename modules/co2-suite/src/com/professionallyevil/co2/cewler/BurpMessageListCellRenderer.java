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

package com.professionallyevil.co2.cewler;


import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import javax.swing.*;
import java.awt.*;

/**
 * ListCellRenderer for IHttpRequestResponse items.  It displays the URL.
 */
public class BurpMessageListCellRenderer extends JLabel implements ListCellRenderer<IHttpRequestResponse> {
    IBurpExtenderCallbacks callbacks;

    BurpMessageListCellRenderer(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public Component getListCellRendererComponent(JList<? extends IHttpRequestResponse> list, IHttpRequestResponse value, int index, boolean isSelected, boolean cellHasFocus) {
        setOpaque(true);
        IRequestInfo request = callbacks.getHelpers().analyzeRequest(value);
        setText(request.getUrl().toString());
        if (isSelected) {
            setBackground(list.getSelectionBackground());
            //setForeground(list.getSelectionForeground());  // this looks inconsistent
        } else {
            setBackground(list.getBackground());
            //setForeground(list.getForeground());
        }
        return this;
    }
}
