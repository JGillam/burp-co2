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

package com.professionallyevil.co2.basicauth;

import com.professionallyevil.co2.Co2Configurable;

import javax.swing.*;
import javax.xml.bind.DatatypeConverter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class BasicAuther implements Co2Configurable{
    private JPanel mainPanel;
    private JTextArea txtUsername;
    private JTextArea txtPasswords;
    private JButton generateButton;
    private JTextArea textOutput;

    public BasicAuther() {
        generateButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String[] users = txtUsername.getText().split("[\n\r]");
                String[] passwords = txtPasswords.getText().split("[\n\r]");
                StringBuilder buf = new StringBuilder();

                for(String user:users){
                    for(String password:passwords){
                        String entry = user + ':' + password;
                        entry = DatatypeConverter.printBase64Binary(entry.getBytes());
                        buf.append(entry).append('\n');
                    }
                }
                textOutput.setText(buf.toString().trim());


            }
        });
    }

    @Override
    public Component getTabComponent() {
        return mainPanel;
    }

    @Override
    public String getTabTitle() {
        return "BasicAuther";
    }
}
