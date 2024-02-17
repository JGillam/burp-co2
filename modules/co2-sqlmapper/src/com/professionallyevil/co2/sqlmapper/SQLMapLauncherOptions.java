/*
 * Copyright (c) 2016 Jason Gillam
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
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class SQLMapLauncherOptions extends JDialog {
    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JTextField textSQLMapPath;
    private JButton browseButton;
    private JComboBox<SQLMapLauncher> comboLaunchType;
    private JTextField textLaunchCommand;
    private JTextField textPythonPath;
    private JButton buttonPythonPath;
    private static final String SETTING_SQLMAP_PATH = SQLMapperForm.SETTING_SQLMAP_PATH;
    private static final String SETTING_SQLMAP_LAUNCHER = SQLMapperForm.SETTING_SQLMAP_LAUNCHER;
    private static final String SETTING_PYTHON_PATH = SQLMapperForm.SETTING_PYTHON_PATH;
    private IBurpExtenderCallbacks callbacks;


    public SQLMapLauncherOptions(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        setContentPane(contentPane);
        setModal(true);
        getRootPane().setDefaultButton(buttonOK);

        String sqlMapPath = callbacks.loadExtensionSetting(SETTING_SQLMAP_PATH);
        textSQLMapPath.setText(sqlMapPath == null ? "" : sqlMapPath);

        String launcherClass = callbacks.loadExtensionSetting(SETTING_SQLMAP_LAUNCHER);

        String pythonPath = callbacks.loadExtensionSetting(SETTING_PYTHON_PATH);
        textPythonPath.setText(pythonPath == null ? "python" : pythonPath);

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
                //String newCmd = ((SQLMapLauncher) comboLaunchType.getSelectedItem()).getLaunchCommand();
                //textLaunchCommand.setText(newCmd == null ? "" : newCmd);
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

        buttonPythonPath.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser chooser = new JFileChooser();
                int result = chooser.showOpenDialog(contentPane);
                if (result == JFileChooser.APPROVE_OPTION) {
                    textPythonPath.setText(chooser.getSelectedFile().getAbsolutePath());
                }
            }
        });
    }

    private void addLaunchers() {
        comboLaunchType.addItem(new ActionScriptSQLMapLauncher());
        comboLaunchType.addItem(new WindowsCmdSQLMapLauncher());
        comboLaunchType.addItem(new XTermLauncher());
        //comboLaunchType.addItem(new CustomSQLMapLauncher());
    }

    private void selectDefaultLauncher(String launcherClass) {
        if (launcherClass == null || launcherClass.isEmpty()) {
            // select by OS
            String os = System.getProperty("os.name");
            callbacks.printOutput("Looking for launcher to match os: " + os);
            for (int i = 0; i < comboLaunchType.getItemCount(); i++) {
                if (comboLaunchType.getItemAt(i).isOSMatch(os)) {
                    comboLaunchType.setSelectedIndex(i);
                    //String newCmd = ((SQLMapLauncher) comboLaunchType.getSelectedItem()).getLaunchCommand();
                    //textLaunchCommand.setText(newCmd == null ? "" : newCmd);
                    break;
                }
            }
        } else {
            for (int i = 0; i < comboLaunchType.getItemCount(); i++) {
                if (launcherClass.equals(comboLaunchType.getItemAt(i).getClass().getName())) {
                    comboLaunchType.setSelectedIndex(i);
                    break;
                }
            }
        }
    }

    private void onOK() {
        callbacks.saveExtensionSetting(SETTING_SQLMAP_PATH, textSQLMapPath.getText());
        callbacks.saveExtensionSetting(SETTING_SQLMAP_LAUNCHER, comboLaunchType.getSelectedItem().getClass().getName());
        callbacks.saveExtensionSetting(SETTING_PYTHON_PATH, textPythonPath.getText());
// add your code here
        dispose();
    }

    private void onCancel() {
// add your code here if necessary
        dispose();
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
        contentPane = new JPanel();
        contentPane.setLayout(new GridLayoutManager(2, 1, new Insets(10, 10, 10, 10), -1, -1));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        contentPane.add(panel1, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, 1, null, null, null, 0, false));
        final Spacer spacer1 = new Spacer();
        panel1.add(spacer1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1, true, false));
        panel1.add(panel2, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        buttonOK = new JButton();
        buttonOK.setText("OK");
        panel2.add(buttonOK, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        buttonCancel = new JButton();
        buttonCancel.setText("Cancel");
        panel2.add(buttonCancel, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new GridLayoutManager(5, 3, new Insets(0, 0, 0, 0), -1, -1));
        contentPane.add(panel3, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setText("SQLMap Path:");
        panel3.add(label1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final Spacer spacer2 = new Spacer();
        panel3.add(spacer2, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_VERTICAL, 1, GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        textSQLMapPath = new JTextField();
        panel3.add(textSQLMapPath, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        browseButton = new JButton();
        browseButton.setText("Browse...");
        panel3.add(browseButton, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Launcher: ");
        panel3.add(label2, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        comboLaunchType = new JComboBox();
        panel3.add(comboLaunchType, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        textLaunchCommand = new JTextField();
        textLaunchCommand.setToolTipText("Use ${SQLMAP} to designate where the sqlmap command will go.");
        textLaunchCommand.setVisible(false);
        panel3.add(textLaunchCommand, new GridConstraints(3, 1, 1, 2, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("Launch Command:");
        label3.setVisible(false);
        panel3.add(label3, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("Python Path:");
        panel3.add(label4, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        textPythonPath = new JTextField();
        textPythonPath.setText("python");
        panel3.add(textPythonPath, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        buttonPythonPath = new JButton();
        buttonPythonPath.setText("Browse...");
        panel3.add(buttonPythonPath, new GridConstraints(2, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return contentPane;
    }

}
