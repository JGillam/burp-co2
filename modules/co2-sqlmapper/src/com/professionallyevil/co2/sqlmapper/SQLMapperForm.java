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
import burp.IExtensionHelpers;
import burp.IParameter;
import burp.IRequestInfo;
import com.professionallyevil.co2.Co2HelpLink;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * User: jasong
 * Date: 1/25/14
 * Time: 9:11 AM
 */
public class SQLMapperForm implements ClipboardOwner, ActionListener, DocumentListener {
    private JTextField sqlmapCommandTxt;
    private JPanel mainPanel;
    private JTextField urlTxt;
    private JTextField dataTxt;
    private JTextField cookieTxt;
    private JCheckBox chkIncludeData;
    private JCheckBox chkIncludeCookies;
    private JTextField txtPinToDBS;
    private JTextField txtPinToTable;
    private JTextField txtPinToUser;
    private JTextField txtPinToCol;
    private JCheckBox chkEnumDBS;
    private JCheckBox chkEnumTables;
    private JCheckBox chkEnumCols;
    private JCheckBox chkEnumCount;
    private JCheckBox chkEnumCurrentUser;
    private JCheckBox chkEnumCurrentDB;
    private JCheckBox chkEnumBanner;
    private JCheckBox chkEnumHostname;
    private JCheckBox chkEnumIsDBA;
    private JCheckBox chkEnumUsers;
    private JCheckBox chkEnumPasswords;
    private JCheckBox chkEnumPrivileges;
    private JCheckBox chkEnumRoles;
    private JCheckBox chkEnumComments;
    private JCheckBox chkEnumSchema;
    private JPanel enumPanel;
    private JCheckBox chkEnumDump;
    private JComboBox cmboDetectionLevel;
    private JComboBox cmboDetectionRisk;
    private JLabel helpSQLMapper;
    private JButton btnRun;
    private JButton configButton;
    private JCheckBox chkTechBoolBlind;
    private JCheckBox chkTechTimeBlind;
    private JCheckBox chkTechUnion;
    private JCheckBox chkTechError;
    private JCheckBox chkTechStacked;
    private JCheckBox chkTechInline;
    private JTextField txtTimeDelay;
    private JTextField txtUnionCols;
    private JTextField txtUnionChar;
    private JTextField txtUnionTable;
    private JTextField txtSecondOrderURL;
    private JCheckBox chkMiscBeep;
    private JCheckBox chkMiscCheckWAF;
    private JCheckBox chkMiscCleanup;
    private JCheckBox chkMiscIndentifyWAF;
    private JCheckBox chkMiscMobile;
    private JCheckBox chkMiscPurgeOutput;
    private JCheckBox chkMiscFlushSession;
    private JTextField txtMatchStringTrue;
    private JTextField txtMatchStringFalse;
    private JTextField txtMatchRegexTrue;
    private JTextField txtMatchCodeTrue;
    private JCheckBox chkCompareTextOnly;
    private JCheckBox chkCompareTitleOnly;
    private JCheckBox chkTestForms;
    private JCheckBox chkMiscFreshQueries;
    private JTextField txtConProxy;
    private JTextField txtConProxyUser;
    private JTextField txtConPasswd;
    private JCheckBox chkIgnoreSysProxy;
    private JComboBox cmboAuthType;
    private JTextField txtAuthUser;
    private JTextField txtAuthPasswd;
    private JTextField txtConTimeout;
    private JTextField txtConDelay;
    private JTextField txtConThreads;
    private JTextField txtEnumWhere;
    private JTextField txtEnumStart;
    private JTextField txtEnumStop;
    private JTextField txtEnumLast;
    private JTextField txtEnumFirst;
    private JTextField txtTestableParameters;
    private JTextField txtSkipParameters;
    private JTextField txtPrefix;
    private JTextField txtSuffix;
    private JTextField txtDBMS;
    private JTextField txtOS;
    private JTextField txtExtra;
    private JTextArea textExtraHeaders;
    private JCheckBox chkRandomUserAgent;
    private JComboBox comboDBMS;
    private JTextField txtDBMSVersion;
    private Map<JCheckBox, String> enumCheckboxes = new HashMap<JCheckBox, String>();
    private Map<JCheckBox, String> techniqueCheckboxes = new HashMap<JCheckBox, String>();
    private Map<JCheckBox, String> generalMiscCheckboxes = new HashMap<JCheckBox, String>();
    private IBurpExtenderCallbacks callbacks;
    public static final String SETTING_SQLMAP_PATH = "sqlmapper.execpath";
    public static final String SETTING_SQLMAP_LAUNCHER = "sqlmapper.launcher";
    public static final String SETTING_PYTHON_PATH = "sqlmapper.pythonpath";
    private boolean windowsQuotes = false;

    public SQLMapperForm(IBurpExtenderCallbacks extenderCallbacks) {
        this.callbacks = extenderCallbacks;
        String os = System.getProperty("os.name");
        windowsQuotes = (os != null && os.startsWith("Windows"));
        final JPopupMenu popup = new JPopupMenu();
        JMenuItem copy = new JMenuItem("Copy all");
        popup.add(copy);
        popup.setInvoker(sqlmapCommandTxt);
        copy.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                StringSelection contents = new StringSelection(sqlmapCommandTxt.getText());
                clipboard.setContents(contents, SQLMapperForm.this);
            }
        });


        sqlmapCommandTxt.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                super.mouseReleased(e);
                if (e.isPopupTrigger()) {
                    showPopup(e);
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                super.mousePressed(e);
                if (e.isPopupTrigger()) {
                    showPopup(e);
                }
            }

            private void showPopup(MouseEvent e) {
                popup.show(e.getComponent(), e.getX(), e.getY());
            }
        });

        // Add listeners for Request / Headers tab
        textExtraHeaders.getDocument().addDocumentListener(this);
        enumCheckboxes.put(chkRandomUserAgent, "--random-agent");  // yes, this isn't an enum checkbox, but it is convenient for now.

        // Add listeners for Detection tab
        cmboDetectionRisk.addActionListener(this);
        cmboDetectionLevel.addActionListener(this);
        txtMatchStringTrue.getDocument().addDocumentListener(this);
        txtMatchStringFalse.getDocument().addDocumentListener(this);
        txtMatchRegexTrue.getDocument().addDocumentListener(this);
        txtMatchCodeTrue.getDocument().addDocumentListener(this);
        chkCompareTitleOnly.addActionListener(this);
        chkCompareTextOnly.addActionListener(this);
        chkTestForms.addActionListener(this);
        comboDBMS.addActionListener(this);
        txtDBMSVersion.getDocument().addDocumentListener(this);
        comboDBMS.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String dbms = comboDBMS.getSelectedItem().toString();
                boolean versionRequired = "MySQL".equals(dbms) || "Microsoft SQL Server".equals(dbms);
                txtDBMSVersion.setEditable(versionRequired);
                txtDBMSVersion.setEnabled(versionRequired);
                if (versionRequired) {
                    JOptionPane.showConfirmDialog(mainPanel, "A version number is required for this database!",
                            "Important", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });

        // Add listeners for Enumeration tab
        enumCheckboxes.put(chkEnumBanner, "-b");
        enumCheckboxes.put(chkEnumCols, "--columns");
        enumCheckboxes.put(chkEnumComments, "--comments");
        enumCheckboxes.put(chkEnumCount, "--count");
        enumCheckboxes.put(chkEnumCurrentDB, "--current-db");
        enumCheckboxes.put(chkEnumCurrentUser, "--current-user");
        enumCheckboxes.put(chkEnumDBS, "--dbs");
        enumCheckboxes.put(chkEnumDump, "--dump");
        enumCheckboxes.put(chkEnumHostname, "--hostname");
        enumCheckboxes.put(chkEnumIsDBA, "--is-dba");
        enumCheckboxes.put(chkEnumPasswords, "--passwords");
        enumCheckboxes.put(chkEnumPrivileges, "--privileges");
        enumCheckboxes.put(chkEnumRoles, "--roles");
        enumCheckboxes.put(chkEnumSchema, "--schema");
        enumCheckboxes.put(chkEnumTables, "--tables");
        enumCheckboxes.put(chkEnumUsers, "--users");
        for (JCheckBox checkbox : enumCheckboxes.keySet()) {
            checkbox.addActionListener(this);
        }
        txtEnumWhere.getDocument().addDocumentListener(this);
        txtEnumFirst.getDocument().addDocumentListener(this);
        txtEnumLast.getDocument().addDocumentListener(this);
        txtEnumStart.getDocument().addDocumentListener(this);
        txtEnumStop.getDocument().addDocumentListener(this);


        // Add listeners for technique tab
        techniqueCheckboxes.put(chkTechBoolBlind, "B");
        techniqueCheckboxes.put(chkTechError, "E");
        techniqueCheckboxes.put(chkTechUnion, "U");
        techniqueCheckboxes.put(chkTechStacked, "S");
        techniqueCheckboxes.put(chkTechTimeBlind, "T");
        techniqueCheckboxes.put(chkTechInline, "Q");
        for (JCheckBox checkbox : techniqueCheckboxes.keySet()) {
            checkbox.addActionListener(this);
        }
        txtSecondOrderURL.getDocument().addDocumentListener(this);
        txtTimeDelay.getDocument().addDocumentListener(this);
        txtUnionChar.getDocument().addDocumentListener(this);
        txtUnionCols.getDocument().addDocumentListener(this);
        txtUnionTable.getDocument().addDocumentListener(this);

        // Listeners for Injection tab
        txtTestableParameters.getDocument().addDocumentListener(this);
        txtSkipParameters.getDocument().addDocumentListener(this);
        txtPrefix.getDocument().addDocumentListener(this);
        txtSuffix.getDocument().addDocumentListener(this);
        txtDBMS.getDocument().addDocumentListener(this);
        txtOS.getDocument().addDocumentListener(this);

        // Add action listeners
        chkIncludeData.addActionListener(this);
        chkIncludeCookies.addActionListener(this);
        cookieTxt.getDocument().addDocumentListener(this);
        dataTxt.getDocument().addDocumentListener(this);
        urlTxt.getDocument().addDocumentListener(this);
        txtPinToCol.getDocument().addDocumentListener(this);
        txtPinToDBS.getDocument().addDocumentListener(this);
        txtPinToTable.getDocument().addDocumentListener(this);
        txtPinToUser.getDocument().addDocumentListener(this);


        // General/Misc actions listeners
        generalMiscCheckboxes.put(chkMiscBeep, "--beep");
        generalMiscCheckboxes.put(chkMiscCheckWAF, "--check-waf");
        generalMiscCheckboxes.put(chkMiscIndentifyWAF, "--identify-waf");
        generalMiscCheckboxes.put(chkMiscCleanup, "--cleanup");
        generalMiscCheckboxes.put(chkMiscMobile, "--mobile");
        generalMiscCheckboxes.put(chkMiscPurgeOutput, "--purge-output");
        generalMiscCheckboxes.put(chkMiscFlushSession, "--flush-session");
        generalMiscCheckboxes.put(chkMiscFreshQueries, "--fresh-queries");

        for (JCheckBox checkbox : generalMiscCheckboxes.keySet()) {
            checkbox.addActionListener(this);
        }

        // Connection listeners
        txtConProxy.getDocument().addDocumentListener(this);
        txtConProxyUser.getDocument().addDocumentListener(this);
        txtConPasswd.getDocument().addDocumentListener(this);
        chkIgnoreSysProxy.addActionListener(this);
        txtAuthUser.getDocument().addDocumentListener(this);
        txtAuthPasswd.getDocument().addDocumentListener(this);
        txtConDelay.getDocument().addDocumentListener(this);
        txtConTimeout.getDocument().addDocumentListener(this);
        txtConThreads.getDocument().addDocumentListener(this);
        cmboAuthType.addActionListener(this);

        txtExtra.getDocument().addDocumentListener(this);

        helpSQLMapper.addMouseListener(new Co2HelpLink("https://github.com/JGillam/burp-co2/wiki/SQLMapper", helpSQLMapper));

        String exec_path = callbacks.loadExtensionSetting(SETTING_SQLMAP_PATH);
        String launcherClass = callbacks.loadExtensionSetting(SETTING_SQLMAP_LAUNCHER);
        btnRun.setEnabled(exec_path != null && !exec_path.isEmpty() && launcherClass != null && !launcherClass.isEmpty());
        btnRun.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String sqlmapPath = callbacks.loadExtensionSetting(SETTING_SQLMAP_PATH);
                String launcherClass = callbacks.loadExtensionSetting(SETTING_SQLMAP_LAUNCHER);
                String pythonPath = callbacks.loadExtensionSetting(SETTING_PYTHON_PATH);
                try {
                    Class<?> clazz = Class.forName(launcherClass);
                    if (SQLMapLauncher.class.isAssignableFrom(clazz) && sqlmapPath != null) {
                        SQLMapLauncher launcher = (SQLMapLauncher) clazz.newInstance();
                        ProcessBuilder pb = new ProcessBuilder();
                        pb.redirectErrorStream(true);
                        pb.command(launcher.getExecCommands(sqlmapCommandTxt.getText(), sqlmapPath, pythonPath));
                        Process p = pb.start();
                        BufferedReader bis = new BufferedReader(new InputStreamReader(p.getInputStream()));
                        String buf;
                        while ((buf = bis.readLine()) != null) {
                            callbacks.printOutput(">" + buf);
                        }

                    } else {
                        if (SQLMapLauncher.class.isAssignableFrom(clazz)) {
                            callbacks.printError("An appropriate launcher is not selected.  Class selected: " + clazz.getName());
                        } else if (sqlmapPath == null || sqlmapPath.isEmpty()) {
                            callbacks.printError("The path to sqlmap.py has not been set.");
                        }
                    }
                } catch (ClassNotFoundException e1) {
                    callbacks.printError(e1.getMessage());
                } catch (InstantiationException e1) {
                    callbacks.printError(e1.getMessage());
                } catch (IllegalAccessException e1) {
                    callbacks.printError(e1.getMessage());
                } catch (IOException e1) {
                    callbacks.printError(e1.getMessage());
                }
            }
        });
        configButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                SQLMapLauncherOptions dialog = new SQLMapLauncherOptions(callbacks);
                dialog.pack();
                dialog.setLocationRelativeTo(mainPanel);
                dialog.setModal(true);
                dialog.setVisible(true);
                String exec_path = callbacks.loadExtensionSetting(SETTING_SQLMAP_PATH);
                String launcherClass = callbacks.loadExtensionSetting(SETTING_SQLMAP_LAUNCHER);
                btnRun.setEnabled(exec_path != null && !exec_path.isEmpty() && launcherClass != null && !launcherClass.isEmpty());
            }
        });

        String[] dbmsOptions = {"Microsoft SQL Server", "MySQL", "Oracle", "PostgreSQL", "SQLite", "Sybase", "HSQLDB",
                "IBM DB2", "Microsoft Access", "Firebird", "SAP MaxDB"};
        new PopupTextHelper(dbmsOptions, txtDBMS);

        String[] osOptions = {"Linux", "Windows"};
        new PopupTextHelper(osOptions, txtOS);
    }

    public JPanel getMainPanel() {
        return mainPanel;
    }

    public void setRequestInfo(IRequestInfo request, IExtensionHelpers helpers) throws URISyntaxException {
        clearFields();
        urlTxt.setText(request.getUrl().toURI().toString());

        List<IParameter> params = request.getParameters();
        StringBuilder body = new StringBuilder();
        StringBuilder cookies = new StringBuilder();
        for (IParameter param : params) {
            if (param.getType() == IParameter.PARAM_BODY) {
                body.append(param.getName());
                body.append('=');
                body.append(param.getValue());
                body.append('&');
            } else if (param.getType() == IParameter.PARAM_COOKIE) {
                cookies.append(param.getName().trim());
                cookies.append('=');
                cookies.append(param.getValue().trim());
                cookies.append(";");
            }
        }
        if (body.length() > 0) {
            body.deleteCharAt(body.length() - 1);
        }
        if (cookies.length() > 1) {
            cookies.deleteCharAt(cookies.length() - 1); //Delete trailing semicolon
        }
        dataTxt.setText(body.toString());
        chkIncludeData.setSelected(dataTxt.getText().length() > 0);

        cookieTxt.setText(cookies.toString().trim());
        chkIncludeCookies.setSelected(cookieTxt.getText().length() > 0);

        buildCommand();
    }

    void buildCommand() {
        StringBuilder buf = new StringBuilder();
        buf.append("-u ");

        buf.append(quotefy(urlTxt.getText()));

        if (chkIncludeData.isSelected() && dataTxt.getText().length() > 0) {
            buf.append(" --data=");
            buf.append(quotefy(dataTxt.getText()));
        }

        // Detection Tab

        if (cmboDetectionLevel.getSelectedIndex() != 0) {     // i.e. not the default
            buf.append(" --level=");
            buf.append(cmboDetectionLevel.getSelectedIndex() + 1);
        }

        if (cmboDetectionRisk.getSelectedIndex() != 0) {      // i.e. not the default
            buf.append(" --risk=");
            buf.append(cmboDetectionRisk.getSelectedItem());
        }

        buf.append(addIfNotEmpty(txtMatchStringTrue, " --string="));
        buf.append(addIfNotEmpty(txtMatchStringFalse, " --not-string="));
        buf.append(addIfNotEmpty(txtMatchRegexTrue, " --regexp="));
        buf.append(addIfNotEmpty(txtMatchCodeTrue, " --code=", false));

        if (chkCompareTextOnly.isSelected()) {
            buf.append(" --text-only");
        }

        if (chkCompareTitleOnly.isSelected()) {
            buf.append(" --titles");
        }

        if (chkTestForms.isSelected()) {
            buf.append(" --forms");
        }

        if (comboDBMS.getSelectedIndex() > 0) {
            String dbms = comboDBMS.getSelectedItem().toString();
            if ("MySQL".equals(dbms) || "Microsoft SQL Server".equals(dbms)) {
                dbms = dbms + " " + txtDBMSVersion.getText().trim();
            }
            buf.append(" --dbms=");
            buf.append(quotefy(dbms));
        }
        // Technique tab

        if (!(chkTechBoolBlind.isSelected() && chkTechError.isSelected() && chkTechInline.isSelected() &&
                chkTechStacked.isSelected() && chkTechTimeBlind.isSelected() && chkTechUnion.isSelected())) {
            buf.append(" --technique=");
            for (JCheckBox chk : techniqueCheckboxes.keySet()) {
                if (chk.isSelected()) {
                    buf.append(techniqueCheckboxes.get(chk));
                }
            }
        }

        if (chkTechUnion.isSelected()) {
            String unionCols = txtUnionCols.getText().trim();
            if (unionCols.length() > 0) {
                buf.append(" --union-cols=");
                buf.append(unionCols);
            }
            String unionChar = txtUnionChar.getText().trim();
            if (unionChar.length() > 0) {
                buf.append(" --union-char=");
                buf.append(unionChar);
            }
            String unionTable = txtUnionTable.getText().trim();
            if (unionTable.length() > 0) {
                buf.append(" --union-from=");
                buf.append(unionTable);
            }
        }

        if (chkTechTimeBlind.isSelected() && txtTimeDelay.getText().trim().length() > 0) {
            buf.append(" --time-sec=");
            buf.append(txtTimeDelay.getText().trim());
        }

        if (txtSecondOrderURL.getText().trim().length() > 0) {
            buf.append(" --second-order=");
            buf.append(txtSecondOrderURL.getText());
        }

        // Injection Tab
        buf.append(addIfNotEmpty(txtTestableParameters, " -p ", true));
        buf.append(addIfNotEmpty(txtSkipParameters, " --skip=", true));
        buf.append(addIfNotEmpty(txtPrefix, " --prefix=", true));
        buf.append(addIfNotEmpty(txtSuffix, " --suffix=", true));
        buf.append(addIfNotEmpty(txtDBMS, " --dbms=", true));
        buf.append(addIfNotEmpty(txtOS, " --os=", true));


        // Enumeration Tab

        if (txtPinToUser.getText().trim().length() > 0) {
            buf.append(" -U ");
            buf.append(txtPinToUser.getText());
        }

        if (txtPinToDBS.getText().trim().length() > 0) {
            buf.append(" -D ");
            buf.append(txtPinToDBS.getText());
        }

        if (txtPinToTable.getText().trim().length() > 0) {
            buf.append(" -T ");
            buf.append(txtPinToTable.getText());
        }

        if (txtPinToCol.getText().trim().length() > 0) {
            buf.append(" -C ");
            buf.append(txtPinToCol.getText());
        }

        for (JCheckBox checkbox : enumCheckboxes.keySet()) {
            if (checkbox.isSelected()) {
                buf.append(" ");
                buf.append(enumCheckboxes.get(checkbox));
            }
        }

        buf.append(addIfNotEmpty(txtEnumWhere, " --where=", true));
        buf.append(addIfNotEmpty(txtEnumFirst, " --first=", false));
        buf.append(addIfNotEmpty(txtEnumLast, " --last=", false));
        buf.append(addIfNotEmpty(txtEnumStart, " --start=", false));
        buf.append(addIfNotEmpty(txtEnumStop, " --stop=", false));

        // General/Misc. Tab
        for (JCheckBox checkbox : generalMiscCheckboxes.keySet()) {
            if (checkbox.isSelected()) {
                buf.append(" ");
                buf.append(generalMiscCheckboxes.get(checkbox));
            }
        }

        // Connection Tab
        if (txtConProxy.getText().trim().length() > 0) {
            buf.append(" --proxy=");
            buf.append(txtConProxy.getText().trim());

            String proxyUser = txtConProxyUser.getText().trim();
            String proxyPasswd = txtConPasswd.getText().trim();
            if (proxyUser.length() > 0 || proxyPasswd.length() > 0) {
                buf.append(" --proxy-cred=");
                buf.append(proxyUser);
                buf.append(":");
                buf.append(proxyPasswd);
            }
        }

        if (chkIgnoreSysProxy.isSelected()) {
            buf.append(" --ignore-proxy");
        }

        if (cmboAuthType.getSelectedIndex() > 0) {
            buf.append(" --auth-type=");
            buf.append(cmboAuthType.getSelectedItem().toString());

            String authUser = txtAuthUser.getText().trim();
            String authPasswd = txtAuthPasswd.getText().trim();

            if (authUser.length() > 0 || authPasswd.length() > 0) {
                buf.append(" --auth-cred=");
                buf.append(authUser);
                buf.append(":");
                buf.append(authPasswd);
            }
        }

        buf.append(addIfNotEmpty(txtConDelay, " --delay=", false));
        buf.append(addIfNotEmpty(txtConTimeout, " --timeout=", false));
        buf.append(addIfNotEmpty(txtConThreads, " --threads=", false));

        buf.append(addIfNotEmpty(txtExtra, " ", false));

        // Handle headers
        String headers = textExtraHeaders.getText();
        if (!headers.isEmpty()) {
            headers = headers.replace("\n", "\\n");
            buf.append(" --headers=");
            buf.append(quotefy(headers));
        }


//        Handle cookies.  This is done last because some cookie characters seem to be problematic.
        if (chkIncludeCookies.isSelected() && cookieTxt.getText().length() > 0) {
            buf.append(" --cookie=");
            buf.append(quotefy(cookieTxt.getText()));
        }

        sqlmapCommandTxt.setText(buf.toString());
    }

    private String quotefy(String input) {
        if (windowsQuotes) {
            input = input.replaceAll("([\"&|><^\\\\])", "^$0");
            return "\"" + input + "\"";
        } else {
            input = input.replace("'", "'\\''");
            return "'" + input + "'";
        }
    }

    public void clearFields() {
        // Clear fields
        urlTxt.setText("");
        cookieTxt.setText("");
        dataTxt.setText("");
        cmboDetectionLevel.setSelectedIndex(0);
        cmboDetectionRisk.setSelectedIndex(0);

        for (JCheckBox checkbox : enumCheckboxes.keySet()) {
            checkbox.setSelected(false);
        }
    }

    private String addIfNotEmpty(JTextComponent textField, String prefix) {
        return addIfNotEmpty(textField, prefix, true);
    }

    private String addIfNotEmpty(JTextComponent textField, String prefix, boolean quotefy) {
        String value = textField.getText().trim();
        if (value.length() > 0) {
            if (quotefy) {
                return prefix + quotefy(value);
            } else {
                return prefix + value;
            }
        } else {
            return "";
        }
    }

    @Override
    public void lostOwnership(Clipboard clipboard, Transferable contents) {

    }


    @Override
    public void actionPerformed(ActionEvent e) {
        buildCommand();
    }

    @Override
    public void insertUpdate(DocumentEvent e) {
        buildCommand();
    }

    @Override
    public void removeUpdate(DocumentEvent e) {
        buildCommand();
    }

    @Override
    public void changedUpdate(DocumentEvent e) {
        buildCommand();
    }


    private void createUIComponents() {
        // TODO: place custom component creation code here
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
        mainPanel.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(6, 1, new Insets(5, 5, 5, 5), -1, -1));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel1, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel1.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "SQLMap Command"));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(2, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel2, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        sqlmapCommandTxt = new JTextField();
        sqlmapCommandTxt.setEditable(false);
        panel2.add(sqlmapCommandTxt, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(panel3, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setText("Extra SQLMap Params:");
        panel3.add(label1, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtExtra = new JTextField();
        txtExtra.setToolTipText("Additional SQLMap command parameters for anything not otherwise found in SQLMapper.");
        panel3.add(txtExtra, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(panel4, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 2, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel4.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Auto Run"));
        btnRun = new JButton();
        btnRun.setText("Run");
        btnRun.setVisible(true);
        panel4.add(btnRun, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        configButton = new JButton();
        configButton.setText("Config");
        configButton.setToolTipText("Configure the settings to auto run.");
        panel4.add(configButton, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer1 = new com.intellij.uiDesigner.core.Spacer();
        mainPanel.add(spacer1, new com.intellij.uiDesigner.core.GridConstraints(5, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel5, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer2 = new com.intellij.uiDesigner.core.Spacer();
        panel5.add(spacer2, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JPanel panel6 = new JPanel();
        panel6.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel5.add(panel6, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel6.setBorder(BorderFactory.createTitledBorder(BorderFactory.createRaisedBevelBorder(), null));
        helpSQLMapper = new JLabel();
        helpSQLMapper.setIcon(new ImageIcon(getClass().getResource("/com/professionallyevil/co2/images/help.png")));
        helpSQLMapper.setText("");
        panel6.add(helpSQLMapper, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JTabbedPane tabbedPane1 = new JTabbedPane();
        mainPanel.add(tabbedPane1, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        tabbedPane1.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Options"));
        final JPanel panel7 = new JPanel();
        panel7.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(10, 8, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane1.addTab("Detection", panel7);
        panel7.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Detection"));
        final JPanel panel8 = new JPanel();
        panel8.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 5, new Insets(0, 0, 0, 0), -1, -1));
        panel7.add(panel8, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 8, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Level:");
        panel8.add(label2, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("Risk:");
        panel8.add(label3, new com.intellij.uiDesigner.core.GridConstraints(0, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        cmboDetectionLevel = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel1 = new DefaultComboBoxModel();
        defaultComboBoxModel1.addElement("1 (default)");
        defaultComboBoxModel1.addElement("2");
        defaultComboBoxModel1.addElement("3");
        defaultComboBoxModel1.addElement("4");
        defaultComboBoxModel1.addElement("5");
        cmboDetectionLevel.setModel(defaultComboBoxModel1);
        panel8.add(cmboDetectionLevel, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        cmboDetectionRisk = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel2 = new DefaultComboBoxModel();
        defaultComboBoxModel2.addElement("1 (default)");
        defaultComboBoxModel2.addElement("0");
        defaultComboBoxModel2.addElement("2");
        defaultComboBoxModel2.addElement("3");
        cmboDetectionRisk.setModel(defaultComboBoxModel2);
        panel8.add(cmboDetectionRisk, new com.intellij.uiDesigner.core.GridConstraints(0, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer3 = new com.intellij.uiDesigner.core.Spacer();
        panel8.add(spacer3, new com.intellij.uiDesigner.core.GridConstraints(0, 4, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer4 = new com.intellij.uiDesigner.core.Spacer();
        panel7.add(spacer4, new com.intellij.uiDesigner.core.GridConstraints(9, 0, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("String match for True:");
        panel7.add(label4, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label5 = new JLabel();
        label5.setText("String match for False:");
        panel7.add(label5, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtMatchStringTrue = new JTextField();
        panel7.add(txtMatchStringTrue, new com.intellij.uiDesigner.core.GridConstraints(1, 2, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        txtMatchStringFalse = new JTextField();
        panel7.add(txtMatchStringFalse, new com.intellij.uiDesigner.core.GridConstraints(2, 2, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label6 = new JLabel();
        label6.setText("Regex match for True:");
        panel7.add(label6, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtMatchRegexTrue = new JTextField();
        panel7.add(txtMatchRegexTrue, new com.intellij.uiDesigner.core.GridConstraints(3, 2, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label7 = new JLabel();
        label7.setText("HTTP Code for True:");
        panel7.add(label7, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtMatchCodeTrue = new JTextField();
        panel7.add(txtMatchCodeTrue, new com.intellij.uiDesigner.core.GridConstraints(4, 2, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        chkCompareTextOnly = new JCheckBox();
        chkCompareTextOnly.setText("Compare on text only.");
        panel7.add(chkCompareTextOnly, new com.intellij.uiDesigner.core.GridConstraints(5, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkCompareTitleOnly = new JCheckBox();
        chkCompareTitleOnly.setText("Compare on titles only.");
        panel7.add(chkCompareTitleOnly, new com.intellij.uiDesigner.core.GridConstraints(6, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkTestForms = new JCheckBox();
        chkTestForms.setText("Test Forms");
        chkTestForms.setToolTipText("Parse and test forms on target URL");
        panel7.add(chkTestForms, new com.intellij.uiDesigner.core.GridConstraints(7, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label8 = new JLabel();
        label8.setText("DBMS:");
        label8.setToolTipText("Specify the DBMS, if known.");
        panel7.add(label8, new com.intellij.uiDesigner.core.GridConstraints(8, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        comboDBMS = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel3 = new DefaultComboBoxModel();
        defaultComboBoxModel3.addElement("- unknown -");
        defaultComboBoxModel3.addElement("MySQL");
        defaultComboBoxModel3.addElement("Oracle");
        defaultComboBoxModel3.addElement("PostgreSQL");
        defaultComboBoxModel3.addElement("Microsoft SQL Server");
        defaultComboBoxModel3.addElement("Microsoft Access");
        defaultComboBoxModel3.addElement("IBM DB2");
        defaultComboBoxModel3.addElement("SQLite");
        defaultComboBoxModel3.addElement("Firebird");
        defaultComboBoxModel3.addElement("Sybase");
        defaultComboBoxModel3.addElement("SAP MaxDB");
        defaultComboBoxModel3.addElement("HSQLDB");
        defaultComboBoxModel3.addElement("Informix");
        comboDBMS.setModel(defaultComboBoxModel3);
        panel7.add(comboDBMS, new com.intellij.uiDesigner.core.GridConstraints(8, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label9 = new JLabel();
        label9.setText("Version:");
        label9.setToolTipText("Version is required for MySQL and Microsoft SQL Server.");
        panel7.add(label9, new com.intellij.uiDesigner.core.GridConstraints(8, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtDBMSVersion = new JTextField();
        txtDBMSVersion.setEditable(false);
        txtDBMSVersion.setEnabled(false);
        panel7.add(txtDBMSVersion, new com.intellij.uiDesigner.core.GridConstraints(8, 4, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(50, -1), null, 0, false));
        final JPanel panel9 = new JPanel();
        panel9.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(10, 4, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane1.addTab("Techniques", panel9);
        chkTechBoolBlind = new JCheckBox();
        chkTechBoolBlind.setSelected(true);
        chkTechBoolBlind.setText("Boolean-based blind (B)");
        panel9.add(chkTechBoolBlind, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer5 = new com.intellij.uiDesigner.core.Spacer();
        panel9.add(spacer5, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer6 = new com.intellij.uiDesigner.core.Spacer();
        panel9.add(spacer6, new com.intellij.uiDesigner.core.GridConstraints(9, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        chkTechTimeBlind = new JCheckBox();
        chkTechTimeBlind.setSelected(true);
        chkTechTimeBlind.setText("Time-based blind (T)");
        panel9.add(chkTechTimeBlind, new com.intellij.uiDesigner.core.GridConstraints(6, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkTechError = new JCheckBox();
        chkTechError.setSelected(true);
        chkTechError.setText("Error-based (E)");
        panel9.add(chkTechError, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkTechUnion = new JCheckBox();
        chkTechUnion.setSelected(true);
        chkTechUnion.setText("Union query-based (U)");
        panel9.add(chkTechUnion, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkTechInline = new JCheckBox();
        chkTechInline.setSelected(true);
        chkTechInline.setText("Inline queries (Q)");
        panel9.add(chkTechInline, new com.intellij.uiDesigner.core.GridConstraints(7, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkTechStacked = new JCheckBox();
        chkTechStacked.setSelected(true);
        chkTechStacked.setText("Stacked queries (S)");
        panel9.add(chkTechStacked, new com.intellij.uiDesigner.core.GridConstraints(5, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label10 = new JLabel();
        label10.setText("Delay (in seconds):");
        panel9.add(label10, new com.intellij.uiDesigner.core.GridConstraints(6, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtTimeDelay = new JTextField();
        txtTimeDelay.setText("");
        txtTimeDelay.setToolTipText("Default is 5 seconds");
        panel9.add(txtTimeDelay, new com.intellij.uiDesigner.core.GridConstraints(6, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label11 = new JLabel();
        label11.setText("Number of Colums:");
        panel9.add(label11, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtUnionCols = new JTextField();
        txtUnionCols.setToolTipText("Default is \"1-10\"");
        panel9.add(txtUnionCols, new com.intellij.uiDesigner.core.GridConstraints(2, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label12 = new JLabel();
        label12.setText("Character (ASCII code):");
        panel9.add(label12, new com.intellij.uiDesigner.core.GridConstraints(3, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtUnionChar = new JTextField();
        txtUnionChar.setToolTipText("By default tests \"0\" (i.e. NULL char). ");
        panel9.add(txtUnionChar, new com.intellij.uiDesigner.core.GridConstraints(3, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label13 = new JLabel();
        label13.setText("Union Table:");
        panel9.add(label13, new com.intellij.uiDesigner.core.GridConstraints(4, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtUnionTable = new JTextField();
        txtUnionTable.setToolTipText("Valid table required in some cases for union queries to work (e.g. users)");
        panel9.add(txtUnionTable, new com.intellij.uiDesigner.core.GridConstraints(4, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label14 = new JLabel();
        label14.setText("Second Order Attack URL:");
        panel9.add(label14, new com.intellij.uiDesigner.core.GridConstraints(8, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtSecondOrderURL = new JTextField();
        panel9.add(txtSecondOrderURL, new com.intellij.uiDesigner.core.GridConstraints(8, 1, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer7 = new com.intellij.uiDesigner.core.Spacer();
        panel9.add(spacer7, new com.intellij.uiDesigner.core.GridConstraints(2, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JPanel panel10 = new JPanel();
        panel10.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(7, 3, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane1.addTab("Injection", panel10);
        final JLabel label15 = new JLabel();
        label15.setText("Testable Parameters:");
        panel10.add(label15, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer8 = new com.intellij.uiDesigner.core.Spacer();
        panel10.add(spacer8, new com.intellij.uiDesigner.core.GridConstraints(0, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer9 = new com.intellij.uiDesigner.core.Spacer();
        panel10.add(spacer9, new com.intellij.uiDesigner.core.GridConstraints(6, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        txtTestableParameters = new JTextField();
        txtTestableParameters.setToolTipText("Use a comma-delimited list here.");
        panel10.add(txtTestableParameters, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label16 = new JLabel();
        label16.setText("Skip Parameters:");
        panel10.add(label16, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtSkipParameters = new JTextField();
        txtSkipParameters.setToolTipText("Use a comma-delimited list here.");
        panel10.add(txtSkipParameters, new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label17 = new JLabel();
        label17.setText("Prefix:");
        panel10.add(label17, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label18 = new JLabel();
        label18.setText("Suffix:");
        panel10.add(label18, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label19 = new JLabel();
        label19.setText("DBMS:");
        panel10.add(label19, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label20 = new JLabel();
        label20.setText("OS:");
        panel10.add(label20, new com.intellij.uiDesigner.core.GridConstraints(5, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtPrefix = new JTextField();
        panel10.add(txtPrefix, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        txtSuffix = new JTextField();
        panel10.add(txtSuffix, new com.intellij.uiDesigner.core.GridConstraints(3, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        txtDBMS = new JTextField();
        panel10.add(txtDBMS, new com.intellij.uiDesigner.core.GridConstraints(4, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        txtOS = new JTextField();
        panel10.add(txtOS, new com.intellij.uiDesigner.core.GridConstraints(5, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JPanel panel11 = new JPanel();
        panel11.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane1.addTab("Enumeration", panel11);
        enumPanel = new JPanel();
        enumPanel.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(7, 4, new Insets(0, 0, 0, 0), -1, -1));
        panel11.add(enumPanel, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        chkEnumDBS = new JCheckBox();
        chkEnumDBS.setText("databases");
        enumPanel.add(chkEnumDBS, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkEnumTables = new JCheckBox();
        chkEnumTables.setText("tables");
        enumPanel.add(chkEnumTables, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkEnumCols = new JCheckBox();
        chkEnumCols.setText("columns");
        enumPanel.add(chkEnumCols, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkEnumCount = new JCheckBox();
        chkEnumCount.setText("count");
        enumPanel.add(chkEnumCount, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkEnumBanner = new JCheckBox();
        chkEnumBanner.setText("banner");
        enumPanel.add(chkEnumBanner, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkEnumIsDBA = new JCheckBox();
        chkEnumIsDBA.setText("is dba");
        enumPanel.add(chkEnumIsDBA, new com.intellij.uiDesigner.core.GridConstraints(0, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkEnumUsers = new JCheckBox();
        chkEnumUsers.setText("users");
        enumPanel.add(chkEnumUsers, new com.intellij.uiDesigner.core.GridConstraints(1, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkEnumPasswords = new JCheckBox();
        chkEnumPasswords.setText("passwords");
        enumPanel.add(chkEnumPasswords, new com.intellij.uiDesigner.core.GridConstraints(2, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkEnumRoles = new JCheckBox();
        chkEnumRoles.setText("roles");
        enumPanel.add(chkEnumRoles, new com.intellij.uiDesigner.core.GridConstraints(0, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkEnumComments = new JCheckBox();
        chkEnumComments.setText("comments");
        enumPanel.add(chkEnumComments, new com.intellij.uiDesigner.core.GridConstraints(1, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkEnumPrivileges = new JCheckBox();
        chkEnumPrivileges.setText("privileges");
        enumPanel.add(chkEnumPrivileges, new com.intellij.uiDesigner.core.GridConstraints(2, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkEnumCurrentUser = new JCheckBox();
        chkEnumCurrentUser.setText("current user");
        enumPanel.add(chkEnumCurrentUser, new com.intellij.uiDesigner.core.GridConstraints(3, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkEnumCurrentDB = new JCheckBox();
        chkEnumCurrentDB.setText("current db");
        enumPanel.add(chkEnumCurrentDB, new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkEnumHostname = new JCheckBox();
        chkEnumHostname.setText("hostname");
        enumPanel.add(chkEnumHostname, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkEnumSchema = new JCheckBox();
        chkEnumSchema.setText("schema");
        enumPanel.add(chkEnumSchema, new com.intellij.uiDesigner.core.GridConstraints(3, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkEnumDump = new JCheckBox();
        chkEnumDump.setText("dump");
        enumPanel.add(chkEnumDump, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer10 = new com.intellij.uiDesigner.core.Spacer();
        enumPanel.add(spacer10, new com.intellij.uiDesigner.core.GridConstraints(6, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JPanel panel12 = new JPanel();
        panel12.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(5, 4, new Insets(0, 0, 0, 0), -1, -1));
        enumPanel.add(panel12, new com.intellij.uiDesigner.core.GridConstraints(5, 0, 1, 4, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel12.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Set limits:"));
        final JLabel label21 = new JLabel();
        label21.setText("Where:");
        panel12.add(label21, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtEnumWhere = new JTextField();
        txtEnumWhere.setToolTipText("Where condition while dumping tables");
        panel12.add(txtEnumWhere, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label22 = new JLabel();
        label22.setText("Start Entry:");
        panel12.add(label22, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label23 = new JLabel();
        label23.setText("Pin to Database:");
        panel12.add(label23, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtPinToDBS = new JTextField();
        panel12.add(txtPinToDBS, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label24 = new JLabel();
        label24.setText("Pin to User:");
        panel12.add(label24, new com.intellij.uiDesigner.core.GridConstraints(0, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtPinToUser = new JTextField();
        panel12.add(txtPinToUser, new com.intellij.uiDesigner.core.GridConstraints(0, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label25 = new JLabel();
        label25.setText("Pin to Table:");
        panel12.add(label25, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtPinToTable = new JTextField();
        panel12.add(txtPinToTable, new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label26 = new JLabel();
        label26.setText("Pin to Column:");
        panel12.add(label26, new com.intellij.uiDesigner.core.GridConstraints(1, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtPinToCol = new JTextField();
        panel12.add(txtPinToCol, new com.intellij.uiDesigner.core.GridConstraints(1, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        txtEnumStart = new JTextField();
        txtEnumStart.setToolTipText("First entry to dump.");
        panel12.add(txtEnumStart, new com.intellij.uiDesigner.core.GridConstraints(3, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label27 = new JLabel();
        label27.setText("Stop Entry:");
        panel12.add(label27, new com.intellij.uiDesigner.core.GridConstraints(3, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtEnumStop = new JTextField();
        txtEnumStop.setToolTipText("Last entry to dump.");
        panel12.add(txtEnumStop, new com.intellij.uiDesigner.core.GridConstraints(3, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label28 = new JLabel();
        label28.setText("First Char:");
        panel12.add(label28, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label29 = new JLabel();
        label29.setText("Last Char:");
        panel12.add(label29, new com.intellij.uiDesigner.core.GridConstraints(4, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtEnumLast = new JTextField();
        txtEnumLast.setToolTipText("Index of last char to dump (for Blind injection only)");
        panel12.add(txtEnumLast, new com.intellij.uiDesigner.core.GridConstraints(4, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        txtEnumFirst = new JTextField();
        txtEnumFirst.setToolTipText("Index of first char to dump (for Blind injection only)");
        panel12.add(txtEnumFirst, new com.intellij.uiDesigner.core.GridConstraints(4, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JPanel panel13 = new JPanel();
        panel13.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(9, 2, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane1.addTab("General/Misc.", panel13);
        chkMiscBeep = new JCheckBox();
        chkMiscBeep.setText("Beep");
        chkMiscBeep.setToolTipText("Make a beep sound when SQL injection is found");
        panel13.add(chkMiscBeep, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer11 = new com.intellij.uiDesigner.core.Spacer();
        panel13.add(spacer11, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer12 = new com.intellij.uiDesigner.core.Spacer();
        panel13.add(spacer12, new com.intellij.uiDesigner.core.GridConstraints(8, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        chkMiscCheckWAF = new JCheckBox();
        chkMiscCheckWAF.setText("Check for WAF");
        chkMiscCheckWAF.setToolTipText("Heuristically check for WAF/IPS/IDS protection.");
        panel13.add(chkMiscCheckWAF, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkMiscCleanup = new JCheckBox();
        chkMiscCleanup.setText("Cleanup");
        chkMiscCleanup.setToolTipText("Clean up the DBMS from sqlmap specific UDF and tables.");
        panel13.add(chkMiscCleanup, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkMiscIndentifyWAF = new JCheckBox();
        chkMiscIndentifyWAF.setText("Identify WAF");
        chkMiscIndentifyWAF.setToolTipText("Thorough testing for WAF/IPS/IDS protection");
        panel13.add(chkMiscIndentifyWAF, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkMiscPurgeOutput = new JCheckBox();
        chkMiscPurgeOutput.setText("Purge Output");
        chkMiscPurgeOutput.setToolTipText("Safely remove all content from output directory.");
        panel13.add(chkMiscPurgeOutput, new com.intellij.uiDesigner.core.GridConstraints(5, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkMiscFlushSession = new JCheckBox();
        chkMiscFlushSession.setText("Flush Session");
        chkMiscFlushSession.setToolTipText("Flush session files for the current target.");
        panel13.add(chkMiscFlushSession, new com.intellij.uiDesigner.core.GridConstraints(6, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkMiscMobile = new JCheckBox();
        chkMiscMobile.setText("Imitate Mobile");
        chkMiscMobile.setToolTipText("Set the HTTP User-Agent header to a smart phone.");
        panel13.add(chkMiscMobile, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkMiscFreshQueries = new JCheckBox();
        chkMiscFreshQueries.setText("Use Fresh Queries");
        chkMiscFreshQueries.setToolTipText("Ignore query results stored in session file.");
        panel13.add(chkMiscFreshQueries, new com.intellij.uiDesigner.core.GridConstraints(7, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel14 = new JPanel();
        panel14.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(9, 6, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane1.addTab("Connection", panel14);
        final com.intellij.uiDesigner.core.Spacer spacer13 = new com.intellij.uiDesigner.core.Spacer();
        panel14.add(spacer13, new com.intellij.uiDesigner.core.GridConstraints(0, 5, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer14 = new com.intellij.uiDesigner.core.Spacer();
        panel14.add(spacer14, new com.intellij.uiDesigner.core.GridConstraints(8, 0, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        chkIgnoreSysProxy = new JCheckBox();
        chkIgnoreSysProxy.setText("Ignore System Proxy");
        panel14.add(chkIgnoreSysProxy, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel15 = new JPanel();
        panel15.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(3, 3, new Insets(0, 0, 0, 0), -1, -1));
        panel14.add(panel15, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 3, 5, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label30 = new JLabel();
        label30.setText("Proxy:");
        panel15.add(label30, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtConProxy = new JTextField();
        txtConProxy.setToolTipText("Specify protocol & port (e.g. http://127.0.0.1:8081)");
        panel15.add(txtConProxy, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label31 = new JLabel();
        label31.setText("User:");
        panel15.add(label31, new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtConProxyUser = new JTextField();
        panel15.add(txtConProxyUser, new com.intellij.uiDesigner.core.GridConstraints(1, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label32 = new JLabel();
        label32.setText("Password:");
        panel15.add(label32, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtConPasswd = new JTextField();
        panel15.add(txtConPasswd, new com.intellij.uiDesigner.core.GridConstraints(2, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JPanel panel16 = new JPanel();
        panel16.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(3, 5, new Insets(0, 0, 0, 0), -1, -1));
        panel14.add(panel16, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 6, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label33 = new JLabel();
        label33.setText("Authentication Type:");
        panel16.add(label33, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        cmboAuthType = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel4 = new DefaultComboBoxModel();
        defaultComboBoxModel4.addElement("None");
        defaultComboBoxModel4.addElement("Basic");
        defaultComboBoxModel4.addElement("Digest");
        defaultComboBoxModel4.addElement("NTLM");
        cmboAuthType.setModel(defaultComboBoxModel4);
        panel16.add(cmboAuthType, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label34 = new JLabel();
        label34.setText("User:");
        panel16.add(label34, new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label35 = new JLabel();
        label35.setText("Password:");
        panel16.add(label35, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtAuthPasswd = new JTextField();
        panel16.add(txtAuthPasswd, new com.intellij.uiDesigner.core.GridConstraints(2, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        txtAuthUser = new JTextField();
        panel16.add(txtAuthUser, new com.intellij.uiDesigner.core.GridConstraints(1, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer15 = new com.intellij.uiDesigner.core.Spacer();
        panel16.add(spacer15, new com.intellij.uiDesigner.core.GridConstraints(0, 4, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JLabel label36 = new JLabel();
        label36.setText("Timeout (seconds):");
        label36.setToolTipText("Connection timeout (default = 30 seconds)");
        panel14.add(label36, new com.intellij.uiDesigner.core.GridConstraints(5, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label37 = new JLabel();
        label37.setText("Delay (seconds):");
        label37.setToolTipText("Delay between HTTP connections (default = none)");
        panel14.add(label37, new com.intellij.uiDesigner.core.GridConstraints(6, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtConTimeout = new JTextField();
        panel14.add(txtConTimeout, new com.intellij.uiDesigner.core.GridConstraints(5, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        txtConDelay = new JTextField();
        panel14.add(txtConDelay, new com.intellij.uiDesigner.core.GridConstraints(6, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label38 = new JLabel();
        label38.setText("Threads:");
        panel14.add(label38, new com.intellij.uiDesigner.core.GridConstraints(7, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtConThreads = new JTextField();
        txtConThreads.setToolTipText("Default = 1");
        panel14.add(txtConThreads, new com.intellij.uiDesigner.core.GridConstraints(7, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label39 = new JLabel();
        label39.setForeground(new Color(-6974059));
        label39.setText("For full details on SQLMap visit http://sqlmap.org");
        mainPanel.add(label39, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JTabbedPane tabbedPane2 = new JTabbedPane();
        mainPanel.add(tabbedPane2, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        tabbedPane2.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Request"));
        final JPanel panel17 = new JPanel();
        panel17.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane2.addTab("Basic", panel17);
        final JPanel panel18 = new JPanel();
        panel18.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(3, 3, new Insets(0, 0, 0, 0), -1, -1));
        panel17.add(panel18, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final JLabel label40 = new JLabel();
        label40.setText("URL: ");
        panel18.add(label40, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        urlTxt = new JTextField();
        urlTxt.setText("");
        panel18.add(urlTxt, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label41 = new JLabel();
        label41.setText("POST Data:");
        panel18.add(label41, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        dataTxt = new JTextField();
        panel18.add(dataTxt, new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label42 = new JLabel();
        label42.setText("Cookies:");
        panel18.add(label42, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        cookieTxt = new JTextField();
        cookieTxt.setToolTipText("Remove spaces between cookies.");
        panel18.add(cookieTxt, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        chkIncludeData = new JCheckBox();
        chkIncludeData.setText("Include");
        panel18.add(chkIncludeData, new com.intellij.uiDesigner.core.GridConstraints(1, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        chkIncludeCookies = new JCheckBox();
        chkIncludeCookies.setText("Include");
        panel18.add(chkIncludeCookies, new com.intellij.uiDesigner.core.GridConstraints(2, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel19 = new JPanel();
        panel19.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(2, 3, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane2.addTab("Headers", panel19);
        final JScrollPane scrollPane1 = new JScrollPane();
        scrollPane1.setToolTipText("Each header should be in the for Key:Value, one on each line.");
        panel19.add(scrollPane1, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 2, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        scrollPane1.setBorder(BorderFactory.createTitledBorder("Extra Headers"));
        textExtraHeaders = new JTextArea();
        scrollPane1.setViewportView(textExtraHeaders);
        final JPanel panel20 = new JPanel();
        panel20.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel19.add(panel20, new com.intellij.uiDesigner.core.GridConstraints(0, 2, 2, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer16 = new com.intellij.uiDesigner.core.Spacer();
        panel20.add(spacer16, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer17 = new com.intellij.uiDesigner.core.Spacer();
        panel19.add(spacer17, new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        chkRandomUserAgent = new JCheckBox();
        chkRandomUserAgent.setText("Use Random User Agent");
        panel19.add(chkRandomUserAgent, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return mainPanel;
    }
}
