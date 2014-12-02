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

package com.professionallyevil.co2.sqlmapper;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.awt.event.*;

public class SQLMapLauncherOptions extends JDialog {
    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JTextField textSQLMapPath;
    private JButton browseButton;
    private JComboBox<SQLMapLauncher> comboLaunchType;
    private JTextField textLaunchCommand;
    private static final String SETTING_SQLMAP_PATH = SQLMapperForm.SETTING_SQLMAP_PATH;
    private static final String SETTING_SQLMAP_LAUNCHER = SQLMapperForm.SETTING_SQLMAP_LAUNCHER;
    private IBurpExtenderCallbacks callbacks;


    public SQLMapLauncherOptions(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        setContentPane(contentPane);
        setModal(true);
        getRootPane().setDefaultButton(buttonOK);

        String sqlMapPath = callbacks.loadExtensionSetting(SETTING_SQLMAP_PATH);
        textSQLMapPath.setText(sqlMapPath == null ? "" : sqlMapPath);

        String launcherClass = callbacks.loadExtensionSetting(SETTING_SQLMAP_LAUNCHER);

        addLaunchers();
        comboLaunchType.setSelectedIndex(0);
        selectDefaultLauncher(launcherClass);

        buttonOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onOK();
            }
        });

        buttonCancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onCancel();
            }
        });

// call onCancel() when cross is clicked
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                onCancel();
            }
        });

// call onCancel() on ESCAPE
        contentPane.registerKeyboardAction(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onCancel();
            }
        }, KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        comboLaunchType.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String newCmd = ((SQLMapLauncher) comboLaunchType.getSelectedItem()).getLaunchCommand();
                textLaunchCommand.setText(newCmd == null ? "" : newCmd);
            }
        });
        browseButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser chooser = new JFileChooser(textSQLMapPath.getText());
                int result = chooser.showOpenDialog(contentPane);
                if (result == JFileChooser.APPROVE_OPTION) {
                    textSQLMapPath.setText(chooser.getSelectedFile().getAbsolutePath());
                }
            }
        });
    }

    private void addLaunchers() {
        comboLaunchType.addItem(new ActionScriptSQLMapLauncher());
        comboLaunchType.addItem(new CustomSQLMapLauncher());
    }

    private void selectDefaultLauncher(String launcherClass) {
        if (launcherClass == null || launcherClass.isEmpty()) {
            // select by OS
            String os = System.getProperty("os.name");
            for (int i = 0; i < comboLaunchType.getItemCount(); i++) {
                if (comboLaunchType.getItemAt(i).isOSMatch(os)) {
                    comboLaunchType.setSelectedIndex(i);
                    String newCmd = ((SQLMapLauncher) comboLaunchType.getSelectedItem()).getLaunchCommand();
                    textLaunchCommand.setText(newCmd == null ? "" : newCmd);
                    break;
                }
            }
        } else {
            for (int i = 0; i < comboLaunchType.getItemCount(); i++) {
                String itemLaunchCommand = comboLaunchType.getItemAt(i).getLaunchCommand();
                if (itemLaunchCommand == null || itemLaunchCommand.equals(launcherClass)) {
                    comboLaunchType.setSelectedIndex(i);
                    break;
                }
            }
        }
    }

    private void onOK() {
        callbacks.saveExtensionSetting(SETTING_SQLMAP_PATH, textSQLMapPath.getText());
        callbacks.saveExtensionSetting(SETTING_SQLMAP_LAUNCHER, comboLaunchType.getSelectedItem().getClass().getName());
// add your code here
        dispose();
    }

    private void onCancel() {
// add your code here if necessary
        dispose();
    }

}
