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

import burp.IBurpExtenderCallbacks;

import javax.swing.*;


/**
 * A go-between class for passing status UI components (text field and progress bar) to SwingWorkers in order to decouple
 * specific instances from the SwingWorker logic.
 */
public class StatusBar{
    private JTextField statusField;
    private JProgressBar progressBar;
    private IBurpExtenderCallbacks callbacks;


    public StatusBar(IBurpExtenderCallbacks callbacks, JTextField statusField, JProgressBar progressBar){
        this.callbacks = callbacks;
        this.statusField = statusField;
        this.progressBar = progressBar;
    }

    public void setStatusText(String text) {
        statusField.setText(text);
    }

    public void setErrorText(String text) {
        statusField.setText(text);
        callbacks.printError(text);
    }

    public JProgressBar getProgressBar(){
        return progressBar;
    }

}
