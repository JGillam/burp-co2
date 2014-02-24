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

package com.secureideas.co2.cewler;

import burp.*;
import com.secureideas.co2.Co2Configurable;
import com.secureideas.co2.StatusBar;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.List;


public class CewlerTab implements Co2Configurable, IContextMenuFactory {
    private JPanel mainPanel;
    private JList<IHttpRequestResponse> responseList;
    private JList<String> wordList;
    private JButton extractWordsButton;
    private JButton clearButton;
    private JProgressBar progressBar;
    private JTextField statusTextField;
    private IBurpExtenderCallbacks callbacks;
    private BurpMessageListModel messageList = new BurpMessageListModel();
    private BurpMessageListCellRenderer messageListCellRenderer;
    private DefaultListModel<String> wordListModel = new DefaultListModel<String>();
    private StatusBar statusBar;

    public CewlerTab(IBurpExtenderCallbacks burpCallbacks) {
        this.callbacks = burpCallbacks;
        statusBar = new StatusBar(callbacks, statusTextField, progressBar);
        messageListCellRenderer = new BurpMessageListCellRenderer(burpCallbacks);
        burpCallbacks.registerContextMenuFactory(this);
        responseList.setCellRenderer(messageListCellRenderer);
        responseList.setModel(messageList);
        wordList.setModel(wordListModel);
        callbacks.printOutput("Cell Renderer" + responseList.getCellRenderer().getClass().getName());
        extractWordsButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                WordExtractorWorker extractor = new WordExtractorWorker(callbacks, statusBar, messageList.getMessages(), new WordExtractorListener() {
                    @Override
                    public void addWords(Set<String> words) {
                        wordListModel.clear();
                        for(String word:words){
                            wordListModel.addElement(word);
                        }
                    }
                });
                extractor.execute();
            }
        });

    }

    @Override
    public Component getTabComponent() {
        return mainPanel;
    }

    @Override
    public String getTabTitle() {
        return "CeWLer";
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();

        if (selectedMessages != null && selectedMessages.length > 0) {
            final List<IHttpRequestResponse> responseMessages = new ArrayList<IHttpRequestResponse>();

            for (IHttpRequestResponse message : selectedMessages) {
                byte[] response = message.getResponse();
                if (response != null && response.length > 0) {
                    responseMessages.add(message);
                }
            }

            if (responseMessages.size() > 0) {
                JMenuItem mi = new JMenuItem("Send to CeWLer");
                mi.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        addMessages(responseMessages);
                    }
                });
                List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
                menuItems.add(mi);
                return menuItems;
            }
        }

        return null;
    }

    private void addMessages(List<IHttpRequestResponse> messages) {
        messageList.addMessages(messages);
        responseList.setCellRenderer(messageListCellRenderer);   // somehow this is getting (annoyingly) unset, so we will just reset it when we change the message list
    }

}
