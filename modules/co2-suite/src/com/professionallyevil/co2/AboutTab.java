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
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;

import javax.swing.*;
import javax.swing.border.TitledBorder;
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
    // private static String VERSION_URI = "http://burpco2.com/latestversions.txt";
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
                    executeLink("https://github.com/JGillam/burp-co2");
                }
            });
            bugTrackingLink.setCursor(new Cursor(Cursor.HAND_CURSOR));
            bugTrackingLink.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    executeLink("https://github.com/JGillam/burp-co2/issues");
                }
            });
            latestVersionLabel.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    executeLink("https://github.com/JGillam/burp-co2/releases");        // TODO: Point this at the latest version notes
                }
            });
        } else {
            additionalInfoLink.setText("CO2 on GitHub");
            bugTrackingLink.setText("https://github.com/JGillam/burp-co2/issues");
        }
        buttonCheckForUpdate.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                versionCheck(false);
            }
        });
        setVersionText(currentVersion.toString() + (CO2Config.isLoadedFromBappStore(burpCallbacks) ? " from BAppStore." : " from jar file."));
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
//                if (autoCheck != chkAutoCheck.isSelected()) {
//                    autoCheck = chkAutoCheck.isSelected();
//                    AboutTab.this.callbacks.saveExtensionSetting(SETTING_UPDATE_CHECK_AUTO, "" + autoCheck);
//                    AboutTab.this.callbacks.printOutput("CO2 automatic version check is now " + (autoCheck ? "on" : "off"));
//                    if (autoCheck) {
//                        versionCheck(false);
//                    }
//                }
            }
        });
    }

    /**
     * Perform a version check.  Look up latest version on the Internet and determine if a update is available.
     */
    public void versionCheck(final boolean automatic) {
        callbacks.printOutput("Version checking has been disabled. Please update with the BAppStore.");
        callbacks.printOutput("CO2 Performing version check.  Your version: " + currentVersion.toString());
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

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new GridLayoutManager(10, 1, new Insets(5, 5, 5, 5), -1, -1));
        mainPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLoweredBevelBorder(), null, TitledBorder.DEFAULT_JUSTIFICATION, TitledBorder.DEFAULT_POSITION, null, null));
        titleLabel = new JLabel();
        titleLabel.setText("<html><h1>About CO<sub>2</sub></h1></html?>");
        mainPanel.add(titleLabel, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        mainPanel.add(spacer1, new GridConstraints(9, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(2, 6, new Insets(0, 0, 0, 0), -1, -1));
        panel1.setVisible(true);
        mainPanel.add(panel1, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setText("Latest Jar Version:");
        label1.setVisible(true);
        panel1.add(label1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        latestVersionLabel = new JLabel();
        latestVersionLabel.setText("Unknown");
        panel1.add(latestVersionLabel, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        buttonCheckForUpdate = new JButton();
        buttonCheckForUpdate.setEnabled(false);
        buttonCheckForUpdate.setText("Check for Updates");
        panel1.add(buttonCheckForUpdate, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setForeground(new Color(-10066330));
        label2.setText("Last Checked:");
        panel1.add(label2, new GridConstraints(0, 3, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        lastCheckedDate = new JLabel();
        lastCheckedDate.setForeground(new Color(-10066330));
        lastCheckedDate.setText("Never");
        panel1.add(lastCheckedDate, new GridConstraints(0, 4, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer2 = new Spacer();
        panel1.add(spacer2, new GridConstraints(0, 5, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        chkAutoCheck = new JCheckBox();
        chkAutoCheck.setEnabled(false);
        chkAutoCheck.setText("Automatically");
        chkAutoCheck.setToolTipText("Check on startup and every 24hrs (does not download)");
        panel1.add(chkAutoCheck, new GridConstraints(1, 2, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("Latest Store Version: ");
        panel1.add(label3, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        latestStoreVersionLabel = new JLabel();
        latestStoreVersionLabel.setText("Unknown");
        panel1.add(latestStoreVersionLabel, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 3, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel2, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("<html>For additional information visit: </html>");
        panel2.add(label4, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer3 = new Spacer();
        panel2.add(spacer3, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        additionalInfoLink = new JLabel();
        additionalInfoLink.setText("https://github.com/JGillam/burp-co2");
        panel2.add(additionalInfoLink, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label5 = new JLabel();
        label5.setText("<html><h2>Bugs and Feature Requests</h2><html>");
        mainPanel.add(label5, new GridConstraints(7, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(1, 3, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel3, new GridConstraints(8, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label6 = new JLabel();
        label6.setText("<html>Bug and feature tracking for CO2 can be found here: ");
        panel3.add(label6, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer4 = new Spacer();
        panel3.add(spacer4, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        bugTrackingLink = new JLabel();
        bugTrackingLink.setText("<html><a href=\"https://github.com/JGillam/burp-co2/issues\">https://github.com/JGillam/burp-co2/issues/</a></html>");
        panel3.add(bugTrackingLink, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label7 = new JLabel();
        label7.setText("<html>\n<h2>License</h2>\n</html>");
        mainPanel.add(label7, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        mainPanel.add(scrollPane1, new GridConstraints(6, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        licenseTextArea = new JTextArea();
        licenseTextArea.setEditable(false);
        licenseTextArea.setEnabled(true);
        licenseTextArea.setLineWrap(true);
        licenseTextArea.setRows(14);
        licenseTextArea.setText("Copyright (c) 2024 Jason Gillam   Licensed under the Apache License, Version 2.0 (the \"License\");  you may not use this file except in compliance with the License.  You may obtain a copy of the License at        http://www.apache.org/licenses/LICENSE-2.0   Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the License for the specific language governing permissions and limitations under the License.");
        scrollPane1.setViewportView(licenseTextArea);
        final JLabel label8 = new JLabel();
        label8.setText("<html><h2>Description</h2>\nCO<sub>2</sub> is a Burp Extension that includes multiple enhancements to Portswigger's Burp Suite Tool.");
        mainPanel.add(label8, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(1, 3, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel4, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label9 = new JLabel();
        label9.setText("Installed Version:");
        panel4.add(label9, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer5 = new Spacer();
        panel4.add(spacer5, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        versionLabel = new JLabel();
        versionLabel.setText("Checking...");
        panel4.add(versionLabel, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return mainPanel;
    }

}
