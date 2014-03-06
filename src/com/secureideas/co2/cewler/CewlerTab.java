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
import com.secureideas.co2.Co2Extender;
import com.secureideas.co2.StatusBar;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.util.*;
import java.util.List;

/**
 * The main tab of CeWLer functionality.
 */
public class CewlerTab implements Co2Configurable, IContextMenuFactory, ClipboardOwner {
    private static final String RESOURCE_FOLDER = "com/secureideas/co2/lists/";
    private JPanel mainPanel;
    private JList<IHttpRequestResponse> responseList;
    private JList<String> wordList;
    private JButton extractWordsButton;
    private JButton clearButton;
    private JProgressBar progressBar;
    private JTextField statusTextField;
    private JSlider minWordSizeSlider;
    private JCheckBox forceToLowercaseCheckBox;
    private JCheckBox ignoreCommonWordsCheckBox;
    private JSlider maxWordSizeSlider;
    private JCheckBox ignoreStyleTagContentsCheckBox;
    private JCheckBox ignoreScriptTagContentsCheckBox;
    private JCheckBox ignoreCommentsCheckBox;
    private JButton saveButton;
    private JCheckBox checkContentTypeCheckBox;
    private IBurpExtenderCallbacks callbacks;
    private BurpMessageListModel messageListModel = new BurpMessageListModel();
    private BurpMessageListCellRenderer messageListCellRenderer;
    private DefaultListModel<String> wordListModel = new DefaultListModel<String>();
    private Set<String> commonWords = new HashSet<String>();
    private StatusBar statusBar;
    private Co2Extender extender;

    public CewlerTab(Co2Extender extender) {
        this.extender = extender;
        this.callbacks = extender.getCallbacks();
        statusBar = new StatusBar(callbacks, statusTextField, progressBar);
        messageListCellRenderer = new BurpMessageListCellRenderer(callbacks);
        callbacks.registerContextMenuFactory(this);
        responseList.setCellRenderer(messageListCellRenderer);
        responseList.setModel(messageListModel);
        wordList.setModel(wordListModel);
        callbacks.printOutput("Cell Renderer" + responseList.getCellRenderer().getClass().getName());
        extractWordsButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                WordExtractorWorker extractor = new WordExtractorWorker(callbacks, statusBar, messageListModel.getMessages(), forceToLowercaseCheckBox.isSelected(), new WordExtractorListener() {
                    @Override
                    public void addWords(Set<String> words) {
                        wordListModel.clear();

                        if (ignoreCommonWordsCheckBox.isSelected()) {
                            words.removeAll(commonWords);
                        }

                        int minWordSize = minWordSizeSlider.getValue();
                        int maxWordSize = maxWordSizeSlider.getValue();

                        for (String word : words) {
                            if (word.length() >= minWordSize && word.length() <= maxWordSize) {   // TODO: add logic to ignore numbers and hex
                                wordListModel.addElement(word);
                            }
                        }
                        statusBar.setStatusText("Words extracted (after filtering): " + wordListModel.getSize());
                    }
                });

                if (ignoreCommonWordsCheckBox.isSelected() && commonWords.isEmpty()) {
                    InputStream inStream = CewlerTab.this.getClass().getClassLoader().getResourceAsStream(RESOURCE_FOLDER + "common_words.txt");
                    BufferedReader reader = new BufferedReader(new InputStreamReader(inStream));

                    try {
                        String line = reader.readLine();
                        while (line != null) {
                            commonWords.add(line.trim());
                            line = reader.readLine();
                        }
                    } catch (IOException e1) {
                        callbacks.printError(e1.toString());
                    }
                }
                extractor.setIgnoreComments(ignoreCommentsCheckBox.isSelected());
                extractor.setIgnoreScriptTags(ignoreScriptTagContentsCheckBox.isSelected());
                extractor.setIgnoreStyleTags(ignoreStyleTagContentsCheckBox.isSelected());
                extractor.setCheckContentType(checkContentTypeCheckBox.isSelected());
                extractor.execute();
            }
        });

        clearButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                messageListModel.clear();
            }
        });

        setupMessagesPopup();
        setupBasicWordsPopup();
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                if (wordListModel.size() > 0) {
                    JFileChooser chooser = new JFileChooser();
                    int result = chooser.showSaveDialog(getTabComponent());
                    if (result == JFileChooser.APPROVE_OPTION) {
                        File f = chooser.getSelectedFile();
                        try {
                            BufferedWriter w = new BufferedWriter(new FileWriter(f));
                            for (int i = 0; i < wordListModel.getSize(); i++) {
                                w.write(wordListModel.get(i));
                                if(i < wordListModel.getSize()) {
                                    w.newLine();
                                }
                            }
                            w.flush();
                            w.close();
                        } catch (IOException e1) {
                            callbacks.printError(e1.toString());
                        }
                    }
                }

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
        messageListModel.addMessages(messages);
        responseList.setCellRenderer(messageListCellRenderer);   // somehow this is getting (annoyingly) unset, so we will just reset it when we change the message list
        extender.selectConfigurableTab(this, false);
    }

    private void setupMessagesPopup() {
        final JPopupMenu popupMsg = new JPopupMenu();

        final Action actionRemoveSelected = new ActionRemoveSelected(responseList, messageListModel);
        popupMsg.add(actionRemoveSelected);

        responseList.addMouseListener(new MouseAdapter() {
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
                popupMsg.setInvoker(wordList);
                actionRemoveSelected.setEnabled(responseList.getSelectedIndices().length > 0);
                popupMsg.show(e.getComponent(), e.getX(), e.getY());
            }
        });

    }

    private void setupBasicWordsPopup() {
        final JPopupMenu popupBWL = new JPopupMenu();

        final Action actionCopyAll = new ActionCopyAll(wordListModel, CewlerTab.this);
        final Action actionCopySelected = new ActionCopySelected(wordList, wordListModel, CewlerTab.this);
        final Action actionRemoveSelected = new ActionRemoveSelected(wordList, wordListModel);

        popupBWL.add(actionCopyAll);
        popupBWL.add(actionCopySelected);
        popupBWL.add(actionRemoveSelected);

        wordList.addMouseListener(new MouseAdapter() {
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
                popupBWL.setInvoker(wordList);
                actionCopyAll.setEnabled(wordListModel.getSize() != 0);
                actionRemoveSelected.setEnabled(wordList.getSelectedIndices().length > 0);
                popupBWL.show(e.getComponent(), e.getX(), e.getY());
            }
        });

    }

    @Override
    public void lostOwnership(Clipboard clipboard, Transferable contents) {
        // do nothing
    }
}
