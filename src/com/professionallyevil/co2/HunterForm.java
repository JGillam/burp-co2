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
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * User: jasong
 * Date: 1/25/14
 * Time: 6:56 PM
 */
public class HunterForm {
    private JPanel mainPanel;
    private JTextField textField1;
    private JButton testButton;
    private JTextArea textArea1;
    private IBurpExtenderCallbacks callbacks;

    public HunterForm() {
        testButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    URL url = new URL(textField1.getText());

                    byte[] request = callbacks.getHelpers().buildHttpRequest(url);
                    byte[] response = callbacks.makeHttpRequest("www.professionallyevil.com", 80, false, request);
                    textArea1.setText(callbacks.getHelpers().bytesToString(response));
                } catch (MalformedURLException e1) {
                    callbacks.printError(e1.getMessage());
                }


            }
        });
    }

    public JPanel getMainPanel() {
        return mainPanel;


    }

    public void setCallbacks(IBurpExtenderCallbacks callbacks){
        this.callbacks = callbacks;
    }
}
