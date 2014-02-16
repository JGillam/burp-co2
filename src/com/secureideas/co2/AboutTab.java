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
import burp.IResponseInfo;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.text.DateFormat;
import java.util.Date;
import java.util.concurrent.ExecutionException;

/**
 * Class to handle the user interface of the About Tab, bound to the IntelliJ AboutTab form
 */
public class AboutTab{

    private JPanel mainPanel;
    private JLabel titleLabel;
    private JLabel versionLabel;
    private JButton buttonCheckForUpdate;
    private JLabel additionalInfoLink;
    private JLabel bugTrackingLink;
    private JTextArea licenseTextArea;
    private JLabel lastCheckedDate;
    private JLabel latestVersionLabel;
    private JCheckBox chkAutoCheck;
    private IBurpExtenderCallbacks callbacks;
    private static String SETTING_LAST_UPDATE_DATE = "co2.about.lastupdate.date";
    private static String SETTING_UPDATE_CHECK_AUTO = "co2.about.lastupdate.auto";
    private DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM);
    private Version currentVersion;
    private boolean autoCheck;

    public AboutTab(IBurpExtenderCallbacks burpCallbacks, Version currentVersion) {
        this.callbacks = burpCallbacks;
        this.currentVersion = currentVersion;
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            additionalInfoLink.setCursor(new Cursor(Cursor.HAND_CURSOR));
            additionalInfoLink.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    executeLink("http://co2.professionallyevil.com");
                }
            });
            bugTrackingLink.setCursor(new Cursor(Cursor.HAND_CURSOR));
            bugTrackingLink.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    executeLink("https://code.google.com/p/burp-co2/");
                }
            });
            latestVersionLabel.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    executeLink("http://co2.professionallyevil.com/download.php");
                }
            });
        } else {
            additionalInfoLink.setText("http://co2.professionallyevil.com");
            bugTrackingLink.setText("https://code.google.com/p/burp-co2/");
        }
        buttonCheckForUpdate.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                versionCheck(false);
            }
        });
        setVersionText(currentVersion.toString());
        String settingLastUpdateDate = burpCallbacks.loadExtensionSetting(SETTING_LAST_UPDATE_DATE);
        if(settingLastUpdateDate != null  && !settingLastUpdateDate.isEmpty()){
            lastCheckedDate.setText(settingLastUpdateDate);
        }

        String autoUpdateCheckSetting =  burpCallbacks.loadExtensionSetting(SETTING_UPDATE_CHECK_AUTO);
        autoCheck = autoUpdateCheckSetting != null && Boolean.parseBoolean(autoUpdateCheckSetting);

        chkAutoCheck.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                if(autoCheck != chkAutoCheck.isSelected()){
                    autoCheck = chkAutoCheck.isSelected();
                    AboutTab.this.callbacks.saveExtensionSetting(SETTING_UPDATE_CHECK_AUTO, "" + autoCheck);
                    AboutTab.this.callbacks.printOutput("Co2 automatic version check is now "+(autoCheck?"on":"off"));
                    if(autoCheck){
                        versionCheck(true);
                    }
                }
            }
        });
    }

    /**
     * Perform a version check.  Look up latest version on the Internet and determine if a update is warranted.
     */
    public void versionCheck(final boolean automatic) {
        callbacks.printOutput("Co2 Performing version check...");

        SwingWorker worker = new SwingWorker() {
            @Override
            protected Object doInBackground() throws Exception {
                URL url = new URL("http://co2.professionallyevil.com/latestversion.txt?v="+
                        currentVersion.getVersionString()+
                        "t="+
                        (automatic?"a":"m")  // reports if automated or manual update, for debugging
                );

                byte[] request = callbacks.getHelpers().buildHttpRequest(url);
                byte[] response = callbacks.makeHttpRequest("co2.professionallyevil.com", 80, false, request);
                IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(response);
                if(responseInfo.getStatusCode() == 200){
                    String body = new String(response).substring(responseInfo.getBodyOffset()).trim();
                    return new Version(body);

                }else{
                    return null;
                }
            }

            @Override
            protected void done() {
                super.done();
                try {
                    Version latestVersion = (Version) get();
                    if(latestVersion!=null){
                        String date = dateFormat.format(new Date());
                        lastCheckedDate.setText(date);
                        callbacks.saveExtensionSetting(SETTING_LAST_UPDATE_DATE, date);
                        if(latestVersion.isNewerThan(currentVersion)){
                            latestVersionLabel.setText("<html><span color=\"red\"><u>"+latestVersion.toString()+"</u></span></html>");
                            latestVersionLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
                            callbacks.printOutput("Co2 Version "+latestVersion.toString()+" is now available.");
                            if(autoCheck){
                                callbacks.issueAlert("Co2 Version "+latestVersion.toString()+" is now available.  See the Co2 About tab for more info.");
                            }
                        }else{
                            latestVersionLabel.setText(latestVersion.toString());
                            latestVersionLabel.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
                        }
                    }else{
                        callbacks.printError("Unable to retrieve version file: "+
                                "http://co2.professionallyevil.com/latestversion.txt");
                        callbacks.issueAlert("Unable to retrieve version file: " +
                                "http://co2.professionallyevil.com/latestversion.txt");
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                } catch (ExecutionException e) {
                    e.printStackTrace();
                }
            }
        };

        worker.execute();
    }

    public JPanel getMainPanel() {
        return mainPanel;
    }

    public void setText(String text) {
        this.titleLabel.setText(text);
    }

    public void setVersionText(String versionText){
        versionLabel.setText(versionText);
    }

    private void executeLink(String urlLink){
        if(Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)){
            URI uri = URI.create(urlLink);
            try {
                Desktop.getDesktop().browse(uri);
            } catch (IOException e) {
                //e.printStackTrace();
                callbacks.printError("Link could not be followed: "+urlLink);
            }
        }
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public boolean isAutoCheck(){
        return autoCheck;
    }

}
