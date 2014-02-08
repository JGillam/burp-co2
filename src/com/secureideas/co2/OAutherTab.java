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
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import com.secureideas.co2.oauth.SignpostBurpHttpRequestWrapper;
import oauth.signpost.OAuthConsumer;
import oauth.signpost.basic.DefaultOAuthConsumer;
import oauth.signpost.exception.OAuthException;
import oauth.signpost.http.HttpRequest;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * User: jasong
 * Date: 2/7/14
 * Time: 10:52 PM
 */
public class OAutherTab implements Co2Configurable, IHttpListener{
    private JPanel mainPanel;
    private JCheckBox enableOAuthWrappingCheckBox;
    private IBurpExtenderCallbacks callbacks;
    private JTextField textConsumerKey;
    private JTextField textConsumerSecret;
    private JTextField textTokenWithSecret;
    private JTextField textTokenSecret;
    private JButton lockButton;
    private JLabel statusLabel;
    private boolean isLocked = false;
    private OAuthConsumer consumer = null;

    public OAutherTab(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        enableOAuthWrappingCheckBox.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                if (enableOAuthWrappingCheckBox.isSelected()) {
                    callbacks.registerHttpListener(OAutherTab.this);
                    callbacks.issueAlert("OAuther enabled");
                }else{
                    callbacks.removeHttpListener(OAutherTab.this);
                    callbacks.issueAlert("OAuther disabled");
                }
            }
        });
        lockButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(isLocked){
                    textConsumerKey.setEnabled(true);
                    textConsumerSecret.setEnabled(true);
                    textTokenWithSecret.setEnabled(true);
                    textTokenSecret.setEnabled(true);
                    lockButton.setText("Lock");
                    statusLabel.setText("Unlocked - enter values and press \"Lock\"");
                    isLocked = false;
                }else{
                    if(textConsumerKey.getText().isEmpty()){
                        statusLabel.setText("<html><span color='red'>Please enter a value for 'Consumer Key'</span></html>");
                    }else if(textConsumerSecret.getText().isEmpty()){
                        statusLabel.setText("<html><span color='red'>Please enter a value for 'Consumer Secret'</span></html>");
                    }else if(textTokenWithSecret.getText().isEmpty()){
                        statusLabel.setText("<html><span color='red'>Please enter a value for 'Token'</span></html>");
                    }else if(textTokenSecret.getText().isEmpty()){
                        statusLabel.setText("<html><span color='red'>Please enter a value for 'Token Secret'</span></html>");
                    }else{
                        try {
                            consumer = new DefaultOAuthConsumer(textConsumerKey.getText(), textConsumerSecret.getText());
                            consumer.setTokenWithSecret(textTokenWithSecret.getText(), textTokenSecret.getText());
                            lockButton.setText("Unlock");
                            statusLabel.setText("<html><span color='blue'>Value locked in!  Press unlock to make changes.</span></html>");
                            textConsumerKey.setEnabled(false);
                            textConsumerSecret.setEnabled(false);
                            textTokenWithSecret.setEnabled(false);
                            textTokenSecret.setEnabled(false);
                            isLocked = true;
                        } catch (Throwable e1) {
                            statusLabel.setText("<html><span color='red'>There is a problem: "+e1.getMessage()+"</span></html>");
                        }

                    }
                }

            }
        });
    }

    public JPanel getMainPanel() {
        return mainPanel;
    }

    @Override
    public Component getTabComponent() {
        return mainPanel;
    }

    @Override
    public String getTabTitle() {
        return "OAuther";
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest && isLocked) {
            HttpRequest req = new SignpostBurpHttpRequestWrapper(messageInfo);

            try {
                consumer.sign(req);
            } catch (OAuthException e) {
                callbacks.printError("OAuth"+e.getMessage());
                callbacks.issueAlert("OAuther could not sign request: "+e.getMessage());
            }

        }
    }
}
