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

        helpSQLMapper.addMouseListener(new Co2HelpLink("http://co2.professionallyevil.com/help-sqlmapper.php", helpSQLMapper));

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
            cookies.deleteCharAt(cookies.length() - 2);
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
            //todo: escape " inside string
            return "\"" + input + "\"";
        } else {
            if (input.contains("'")) {
                return "\"" + input + "\"";

            } else {
                return "'" + input + "'";
            }
        }
    }

    public void clearFields() {
        // Clear fields
        urlTxt.setText("");
        cookieTxt.setText("");
        dataTxt.setText("");
        cmboDetectionLevel.setSelectedIndex(0);
        cmboDetectionRisk.setSelectedIndex(1);

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
}
