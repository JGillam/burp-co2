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
public class AboutTab {

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
    private JLabel latestStoreVersionLabel;
    private IBurpExtenderCallbacks callbacks;
    private static String SETTING_LAST_UPDATE_DATE = "co2.about.lastupdate.date";
    private static String SETTING_UPDATE_CHECK_AUTO = "co2.about.lastupdate.auto";
    private static String VERSION_URI = "http://www.burpco2.com/latestversions.txt";
    private DateFormat dateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.MEDIUM);
    private Version currentVersion;
    private boolean autoCheck;

    public AboutTab(IBurpExtenderCallbacks burpCallbacks, Version currentVersion, String build) {
        this.callbacks = burpCallbacks;
        this.currentVersion = currentVersion;
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            additionalInfoLink.setCursor(new Cursor(Cursor.HAND_CURSOR));
            additionalInfoLink.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    executeLink("http://www.burpco2.com?src=co2");
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
                    executeLink("http://www.burpco2.com?src=co2");           // TODO: Point this at the latest version notes
                }
            });
        } else {
            additionalInfoLink.setText("www.burpco2.com.com");
            bugTrackingLink.setText("https://code.google.com/p/burp-co2/");
        }
        buttonCheckForUpdate.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                versionCheck(false);
            }
        });
        setVersionText(currentVersion.toString() + " (build " + build + ")" + (CO2Config.isLoadedFromBappStore() ? " from BAppStore." : " from jar file."));
        String settingLastUpdateDate = burpCallbacks.loadExtensionSetting(SETTING_LAST_UPDATE_DATE);
        if (settingLastUpdateDate != null && !settingLastUpdateDate.isEmpty()) {
            lastCheckedDate.setText(settingLastUpdateDate);
        }

        String autoUpdateCheckSetting = burpCallbacks.loadExtensionSetting(SETTING_UPDATE_CHECK_AUTO);
        autoCheck = autoUpdateCheckSetting != null && Boolean.parseBoolean(autoUpdateCheckSetting);
        chkAutoCheck.setSelected(autoCheck);

        chkAutoCheck.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                if (autoCheck != chkAutoCheck.isSelected()) {
                    autoCheck = chkAutoCheck.isSelected();
                    AboutTab.this.callbacks.saveExtensionSetting(SETTING_UPDATE_CHECK_AUTO, "" + autoCheck);
                    AboutTab.this.callbacks.printOutput("CO2 automatic version check is now " + (autoCheck ? "on" : "off"));
                    if (autoCheck) {
                        versionCheck(true);
                    }
                }
            }
        });
    }

    /**
     * Perform a version check.  Look up latest version on the Internet and determine if a update is available.
     */
    public void versionCheck(final boolean automatic) {
        callbacks.printOutput("CO2 Performing version check.  Your version: " + currentVersion.toString());
        latestVersionLabel.setText("Checking...");
        latestStoreVersionLabel.setText("Checking...");

        SwingWorker worker = new SwingWorker() {
            @Override
            protected Object doInBackground() throws Exception {
                URL url = new URL(VERSION_URI + "?v=" +
                        currentVersion.getVersionString() +
                        "&t=" +
                        (automatic ? "a" : "m") + // reports if automated or manual update
                        "&b=" +
                        (CO2Config.isLoadedFromBappStore() ? "y" : "n") // loaded from a bappstore version?
                );

                byte[] request = callbacks.getHelpers().buildHttpRequest(url);
                byte[] response = callbacks.makeHttpRequest("www.burpco2.com", 80, false, request);
                IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(response);
                if (responseInfo.getStatusCode() == 200) {
                    String body = new String(response).substring(responseInfo.getBodyOffset()).trim();
                    String[] versionText = body.split(",");
                    Version[] versions = new Version[versionText.length];
                    for (int i = 0; i < versions.length; i++) {
                        versions[i] = new Version(versionText[i]);
                    }
                    return versions;

                } else {
                    return null;
                }
            }

            @Override
            protected void done() {
                super.done();
                try {
                    Version[] latestVersions = (Version[]) get();
                    if (latestVersions != null && latestVersions.length == 2) {   // don't process if we don't have 2
                        String date = dateFormat.format(new Date());
                        lastCheckedDate.setText(date);
                        callbacks.saveExtensionSetting(SETTING_LAST_UPDATE_DATE, date);
                        boolean isBappStoreVersion = CO2Config.isLoadedFromBappStore();
                        if (isBappStoreVersion) {
                            if (latestVersions[1].isNewerThan(currentVersion)) {
                                latestStoreVersionLabel.setText("<html><span color=\"red\"><u>" + latestVersions[1].toString() + "</u></span></html>");
                                //latestStoreVersionLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
                                callbacks.printOutput("CO2 Version " + latestVersions[1].toString() + " is now available on the BAppStore.");
                                if (autoCheck) {
                                    callbacks.issueAlert("CO2 Version " + latestVersions[1].toString() + " is now available on the BAppStore.  See the CO2 About tab for more info.");
                                }
                            } else {
                                latestStoreVersionLabel.setText(latestVersions[1].toString());
                            }
                            latestVersionLabel.setText(latestVersions[0].toString());
                        } else {
                            if (latestVersions[0].isNewerThan(currentVersion)) {
                                latestVersionLabel.setText("<html><span color=\"red\"><u>" + latestVersions[0].toString() + "</u></span></html>");
                                latestVersionLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
                                callbacks.printOutput("CO2 Version " + latestVersions[0].toString() + " is now available.");
                                if (autoCheck) {
                                    callbacks.issueAlert("CO2 Version " + latestVersions[0].toString() + " is now available.  See the CO2 About tab for more info.");
                                }
                            } else {
                                latestVersionLabel.setText(latestVersions[0].toString());
                                latestVersionLabel.setCursor(new Cursor(Cursor.DEFAULT_CURSOR));
                            }
                            latestStoreVersionLabel.setText(latestVersions[1].toString());
                        }
                    } else {
                        callbacks.printError("Unable to retrieve versions from: " +
                                VERSION_URI);
                        callbacks.issueAlert("Unable to retrieve versions from: " +
                                VERSION_URI);
                        latestVersionLabel.setText("Unknown");
                        latestStoreVersionLabel.setText("Unknown");

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

    public void setVersionText(String versionText) {
        versionLabel.setText(versionText);
    }

    private void executeLink(String urlLink) {
        if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            URI uri = URI.create(urlLink);
            try {
                Desktop.getDesktop().browse(uri);
            } catch (IOException e) {
                //e.printStackTrace();
                callbacks.printError("Link could not be followed: " + urlLink);
            }
        }
    }

    public IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public boolean isAutoCheck() {
        return autoCheck;
    }

}
