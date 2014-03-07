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

import burp.IExtensionHelpers;
import burp.IParameter;
import burp.IRequestInfo;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URISyntaxException;
import java.util.*;
import java.util.List;

/**
 * User: jasong
 * Date: 1/25/14
 * Time: 9:11 AM
 */
public class SQLMapperForm implements ClipboardOwner, ActionListener, DocumentListener{
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
    private JCheckBox chkDetectLevel;
    private JCheckBox chkDetectRisk;
    private Map<JCheckBox, String> enumCheckboxes = new HashMap<JCheckBox,String>();


    public SQLMapperForm() {
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
                if(e.isPopupTrigger()){
                    showPopup(e);
                }
            }

            @Override
            public void mousePressed(MouseEvent e) {
                super.mousePressed(e);
                if(e.isPopupTrigger()){
                    showPopup(e);
                }
            }

            private void showPopup(MouseEvent e){
                popup.show(e.getComponent(), e.getX(), e.getY());
            }
        });


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
        for(JCheckBox checkbox: enumCheckboxes.keySet()){
            checkbox.addActionListener(this);
        }

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

        chkDetectLevel.addActionListener(this);
        chkDetectRisk.addActionListener(this);
        cmboDetectionRisk.addActionListener(this);
        cmboDetectionLevel.addActionListener(this);
        cmboDetectionLevel.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                chkDetectLevel.setSelected(true);
            }
        });
        cmboDetectionRisk.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                chkDetectRisk.setSelected(true);
            }
        });

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
        for(IParameter param: params){
            if(param.getType() == IParameter.PARAM_BODY) {
                body.append(param.getName());
                body.append('=');
                body.append(param.getValue());
                body.append('&');
            } else if (param.getType() == IParameter.PARAM_COOKIE) {
                cookies.append(param.getName());
                cookies.append('=');
                cookies.append(param.getValue());
                cookies.append("; ");
            }
        }
        if(body.length()>0){
            body.deleteCharAt(body.length()-1);
        }
        if(cookies.length()>1){
            cookies.deleteCharAt(cookies.length()-2);
        }
        dataTxt.setText(body.toString());
        chkIncludeData.setSelected(dataTxt.getText().length()>0);

        cookieTxt.setText(cookies.toString().trim());
        chkIncludeCookies.setSelected(cookieTxt.getText().length()>0);

        buildCommand();
    }

    void buildCommand(){
        StringBuilder buf = new StringBuilder();
        buf.append("-u ");
        buf.append(quotefy(urlTxt.getText()));

        if(chkIncludeData.isSelected() && dataTxt.getText().length()>0){
            buf.append(" --data=");
            buf.append(quotefy(dataTxt.getText()));
        }

        if(chkIncludeCookies.isSelected() && cookieTxt.getText().length()>0){
            buf.append(" --cookie=");
            buf.append(quotefy(cookieTxt.getText()));
        }

        if(chkDetectLevel.isSelected()) {
            buf.append(" --level=");
            buf.append(cmboDetectionLevel.getSelectedIndex()+1);
        }

        if(chkDetectRisk.isSelected()) {
            buf.append(" --risk=");
            buf.append(cmboDetectionRisk.getSelectedIndex());
        }

        if(txtPinToUser.getText().trim().length()>0){
            buf.append(" -U ");
            buf.append(txtPinToUser.getText());
        }

        if(txtPinToDBS.getText().trim().length()>0){
            buf.append(" -D ");
            buf.append(txtPinToDBS.getText());
        }

        if(txtPinToTable.getText().trim().length()>0){
            buf.append(" -T ");
            buf.append(txtPinToTable.getText());
        }

        if(txtPinToCol.getText().trim().length()>0) {
            buf.append(" -C ");
            buf.append(txtPinToCol.getText());
        }

        for(JCheckBox checkbox: enumCheckboxes.keySet()){
            if(checkbox.isSelected()) {
                buf.append(" ");
                buf.append(enumCheckboxes.get(checkbox));
            }
        }
        sqlmapCommandTxt.setText(buf.toString());
    }

    private String quotefy(String input){
        if(input.contains("'")){
            return "\""+input+"\"";

        }else{
            return "'"+input+"'";
        }
    }

    public void clearFields(){
        // Clear fields
        urlTxt.setText("");
        cookieTxt.setText("");
        dataTxt.setText("");
        cmboDetectionLevel.setSelectedIndex(0);
        cmboDetectionRisk.setSelectedIndex(1);
        chkDetectLevel.setSelected(false);
        chkDetectRisk.setSelected(false);

        for(JCheckBox checkbox: enumCheckboxes.keySet()){
            checkbox.setSelected(false);
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


}
