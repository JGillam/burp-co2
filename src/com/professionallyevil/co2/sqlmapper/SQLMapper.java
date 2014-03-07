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

import burp.*;
import com.professionallyevil.co2.Co2Configurable;
import com.professionallyevil.co2.Co2Extender;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.List;

/**
 * Handler class for SQLMapper tab setup and context menu.
 */
public class SQLMapper implements Co2Configurable, IContextMenuFactory {

    SQLMapperForm tab = new SQLMapperForm();
    IExtensionHelpers helpers;
    Co2Extender extender;

    public SQLMapper(IExtensionHelpers helpers, Co2Extender extender){
        this.helpers = helpers;
        this.extender = extender;
    }

    @Override
    public Component getTabComponent() {
        return tab.getMainPanel();
    }

    @Override
    public String getTabTitle() {
        return "SQLMapper";
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if(messages != null && messages.length > 0) {
            extender.getCallbacks().printOutput("Messages in array: "+messages.length);
            List<JMenuItem> list = new ArrayList<JMenuItem>();
            final IHttpService service = messages[0].getHttpService();
            final byte[] selectedRequest = messages[0].getRequest();
            JMenuItem menuItem = new JMenuItem("Send to SQLMapper (request)");
            menuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    try {
                        IRequestInfo request = helpers.analyzeRequest(service, selectedRequest);
                         extender.getCallbacks().printOutput("SQLMapper analyzed request: "+request.toString());
                        tab.setRequestInfo(request, helpers);
                        extender.selectConfigurableTab(SQLMapper.this, true);
                    } catch (Exception e1) {
                        extender.getCallbacks().printError(e1.getMessage());
                    }
                }
            });
            list.add(menuItem);
            return list;
        }

        return null;
    }
}
