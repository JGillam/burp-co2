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

package com.professionallyevil.co2.cewler;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import com.professionallyevil.co2.Co2Configurable;
import com.professionallyevil.co2.Co2Extender;
import com.professionallyevil.co2.Co2HelpLink;
import com.professionallyevil.co2.StatusBar;

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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The main tab of CeWLer functionality.
 */
public class CewlerTab implements Co2Configurable, IContextMenuFactory, ClipboardOwner {
    private static final String RESOURCE_FOLDER = "com/professionallyevil/co2/lists/";
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
    private JLabel cewlerHelp;
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
        //callbacks.printOutput("Cell Renderer" + responseList.getCellRenderer().getClass().getName());
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
                                if (i < wordListModel.getSize()) {
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
        cewlerHelp.addMouseListener(new Co2HelpLink("https://github.com/JGillam/burp-co2/wiki/CeWLer", cewlerHelp));
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

    @Override
    public String getTabCaption() {
        return getTabTitle();
    }

    @Override
    public Component getUiComponent() {
        return getTabComponent();
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
        mainPanel.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(5, 1, new Insets(5, 5, 5, 5), -1, -1));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel1, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel1.setBorder(BorderFactory.createTitledBorder("Status:"));
        progressBar = new JProgressBar();
        panel1.add(progressBar, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        statusTextField = new JTextField();
        statusTextField.setEditable(false);
        panel1.add(statusTextField, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JSplitPane splitPane1 = new JSplitPane();
        mainPanel.add(splitPane1, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 2, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(12, 2, new Insets(0, 0, 0, 0), -1, -1));
        splitPane1.setLeftComponent(panel2);
        panel2.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Extract From"));
        final JScrollPane scrollPane1 = new JScrollPane();
        panel2.add(scrollPane1, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, new Dimension(-1, 120), null, null, 0, false));
        responseList = new JList();
        responseList.setSelectionMode(2);
        scrollPane1.setViewportView(responseList);
        extractWordsButton = new JButton();
        extractWordsButton.setText("Extract Words");
        panel2.add(extractWordsButton, new com.intellij.uiDesigner.core.GridConstraints(11, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        clearButton = new JButton();
        clearButton.setText("Clear");
        clearButton.setToolTipText("Clear this list and start over");
        panel2.add(clearButton, new com.intellij.uiDesigner.core.GridConstraints(11, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        minWordSizeSlider = new JSlider();
        minWordSizeSlider.setMajorTickSpacing(1);
        minWordSizeSlider.setMaximum(5);
        minWordSizeSlider.setMinimum(1);
        minWordSizeSlider.setPaintLabels(true);
        minWordSizeSlider.setPaintTicks(true);
        minWordSizeSlider.setSnapToTicks(true);
        minWordSizeSlider.setValue(3);
        panel2.add(minWordSizeSlider, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setText("Minimum Word Size to Extract:");
        panel2.add(label1, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        forceToLowercaseCheckBox = new JCheckBox();
        forceToLowercaseCheckBox.setText("Force to Lowercase");
        forceToLowercaseCheckBox.setToolTipText("Convert all words to lowercase.");
        panel2.add(forceToLowercaseCheckBox, new com.intellij.uiDesigner.core.GridConstraints(5, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        ignoreCommonWordsCheckBox = new JCheckBox();
        ignoreCommonWordsCheckBox.setSelected(true);
        ignoreCommonWordsCheckBox.setText("Ignore Common Words");
        ignoreCommonWordsCheckBox.setToolTipText("Ignore words that are very common to the english language.");
        panel2.add(ignoreCommonWordsCheckBox, new com.intellij.uiDesigner.core.GridConstraints(6, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        maxWordSizeSlider = new JSlider();
        maxWordSizeSlider.setMajorTickSpacing(1);
        maxWordSizeSlider.setMaximum(20);
        maxWordSizeSlider.setMinimum(6);
        maxWordSizeSlider.setPaintLabels(true);
        maxWordSizeSlider.setPaintTicks(true);
        maxWordSizeSlider.setSnapToTicks(true);
        maxWordSizeSlider.setValue(20);
        panel2.add(maxWordSizeSlider, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Maximum Word Size to Extract:");
        panel2.add(label2, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        ignoreStyleTagContentsCheckBox = new JCheckBox();
        ignoreStyleTagContentsCheckBox.setSelected(true);
        ignoreStyleTagContentsCheckBox.setText("Ignore <style> Tag Contents");
        panel2.add(ignoreStyleTagContentsCheckBox, new com.intellij.uiDesigner.core.GridConstraints(7, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        ignoreScriptTagContentsCheckBox = new JCheckBox();
        ignoreScriptTagContentsCheckBox.setSelected(true);
        ignoreScriptTagContentsCheckBox.setText("Ignore <script> Tag Contents");
        panel2.add(ignoreScriptTagContentsCheckBox, new com.intellij.uiDesigner.core.GridConstraints(8, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        ignoreCommentsCheckBox = new JCheckBox();
        ignoreCommentsCheckBox.setSelected(false);
        ignoreCommentsCheckBox.setText("Ignore Comments");
        panel2.add(ignoreCommentsCheckBox, new com.intellij.uiDesigner.core.GridConstraints(10, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        checkContentTypeCheckBox = new JCheckBox();
        checkContentTypeCheckBox.setSelected(true);
        checkContentTypeCheckBox.setText("Check Content Type");
        checkContentTypeCheckBox.setToolTipText("Skip script and binary content types");
        panel2.add(checkContentTypeCheckBox, new com.intellij.uiDesigner.core.GridConstraints(9, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        splitPane1.setRightComponent(panel3);
        panel3.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Custom Word List"));
        final JScrollPane scrollPane2 = new JScrollPane();
        panel3.add(scrollPane2, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        wordList = new JList();
        scrollPane2.setViewportView(wordList);
        saveButton = new JButton();
        saveButton.setText("Save...");
        panel3.add(saveButton, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer1 = new com.intellij.uiDesigner.core.Spacer();
        mainPanel.add(spacer1, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, new Dimension(-1, 100), null, null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel4, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer2 = new com.intellij.uiDesigner.core.Spacer();
        panel4.add(spacer2, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel4.add(panel5, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel5.setBorder(BorderFactory.createTitledBorder(BorderFactory.createRaisedBevelBorder(), null));
        cewlerHelp = new JLabel();
        cewlerHelp.setIcon(new ImageIcon(getClass().getResource("/com/professionallyevil/co2/images/help.png")));
        cewlerHelp.setText("");
        panel5.add(cewlerHelp, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return mainPanel;
    }
}
