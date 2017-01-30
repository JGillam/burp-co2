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

package com.professionallyevil.co2.namemangler;

import burp.IBurpExtenderCallbacks;
import com.professionallyevil.co2.Co2Configurable;
import com.professionallyevil.co2.Co2HelpLink;

import javax.swing.*;
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
import java.io.StringReader;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutionException;

/**
 * The NameMangler is a module for generating a list of potential usernames given a list of known users.  It will generate
 * a list using combinations of first and last name, plus initials, etc...
 */
public class NameManglerTab implements Co2Configurable, ClipboardOwner {
    private JPanel mainPanel;
    private JTextArea inputText;
    private JTextArea outputText;
    private JButton mangleButton;
    private JTextArea domains;
    private JCheckBox caseSensitiveCheckBox;
    private JCheckBox numericSuffixesCheckBox;
    private JCheckBox yearSuffixesCheckBox;
    private JTextField delimitersText;
    private JPanel helpNameMangler;
    private IBurpExtenderCallbacks callbacks;
    private int thisYear;

    public NameManglerTab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        mangleButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                List<String> nameList = parseLines(inputText.getText());
                List<String> domainList = parseLines(domains.getText());
                mangleNames(nameList, domainList);
            }
        });

        final JPopupMenu popup = new JPopupMenu();
        JMenuItem copy = new JMenuItem("Copy all");
        popup.add(copy);
        popup.setInvoker(outputText);
        copy.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                StringSelection contents = new StringSelection(outputText.getText());
                clipboard.setContents(contents, NameManglerTab.this);
            }
        });


        outputText.addMouseListener(new MouseAdapter() {
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

        thisYear = Calendar.getInstance().get(Calendar.YEAR);
        helpNameMangler.addMouseListener(new Co2HelpLink("http://co2.professionallyevil.com/help-namemangler.php", helpNameMangler));
    }

    private List<String> parseLines(String blockOfText) {
        List<String> lines = new ArrayList<String>();
        BufferedReader reader = new BufferedReader(new StringReader(blockOfText));
        String name;
        try {
            while ((name = reader.readLine()) != null) {
                lines.add(name);
                //callbacks.printOutput("Added name " + name);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return lines;
    }

    private void mangleNames(final List<String> nameList, final List<String> domainList) {
        //callbacks.printOutput("Mangling names " + nameList.size());
        SwingWorker worker = new SwingWorker() {
            @Override
            protected Object doInBackground() throws Exception {
                Set<String> mangledNames = new TreeSet<String>();

                for (String name : nameList) {
                    String[] parts = name.split(" ");

                    String first = "";
                    if (parts.length > 0) {
                        first = parts[0];
                    }
                    String last = "";
                    String middle = "";
                    if (parts.length == 2) {
                        last = parts[1];
                    } else if (parts.length > 2) {    // todo: handle hyphenated surnames
                        last = parts[2];
                        middle = parts[1];
                        if (middle.endsWith(".")) {
                            middle = middle.substring(0, middle.length() - 1);
                        }
                    }
                    addVariations(mangledNames, first, middle, last, "");
                    for (String domain : domainList) {
                        addVariations(mangledNames, first, middle, last, "@" + domain);
                    }

                }

                StringBuilder buf = new StringBuilder();
                for (String name : mangledNames) {
                    buf.append(name);
                    buf.append('\n');
                }

                return buf.toString().trim();
            }

            private void addVariations(Set<String> mangledNames, String first, String middle, String last, String domain) {
                addVariations(mangledNames, first, middle, last, domain, "");
                String delimiters = delimitersText.getText();
                for (int i = 0; i < delimiters.length(); i++) {
                    addVariations(mangledNames, first, middle, last, domain, delimiters.substring(i, i + 1));
                }

            }

            private void addVariations(Set<String> mangledNames, String first, String middle, String last, String domain, String delim) {
                // first or last
                mangledNames.add(first.toLowerCase() + domain);
                mangledNames.add(last.toLowerCase() + domain);
                if (caseSensitiveCheckBox.isSelected()) {
                    mangledNames.add(toMixedCase(first) + domain);
                    mangledNames.add(first.toUpperCase() + domain);
                    mangledNames.add(toMixedCase(last) + domain);
                    mangledNames.add(last.toLowerCase() + domain);
                }

                // first and last
                mangledNames.add(first.toLowerCase() + delim + last.toLowerCase() + domain);
                mangledNames.add(first.substring(0, 1).toLowerCase() + delim + last.toLowerCase() + domain);
                mangledNames.add(last.toLowerCase() + delim + first.substring(0, 1).toLowerCase() + domain);
                mangledNames.add(first.toLowerCase() + delim + last.substring(0, 1).toLowerCase() + domain);
                if (caseSensitiveCheckBox.isSelected()) {
                    mangledNames.add(toMixedCase(first) + delim + toMixedCase(last) + domain);
                    mangledNames.add(first.substring(0, 1).toUpperCase() + delim + last.toLowerCase() + domain);
                    mangledNames.add(first.substring(0, 1).toUpperCase() + delim + last.toUpperCase() + domain);
                    mangledNames.add(toMixedCase(last) + delim + first.substring(0, 1).toLowerCase() + domain);
                    mangledNames.add(toMixedCase(last) + delim + first.substring(0, 1).toUpperCase() + domain);
                }

                // first, middle, last
                if (middle.length() > 0) {
                    mangledNames.add(first.toLowerCase() + delim + middle.toLowerCase() + delim + last.toLowerCase() + domain);
                    mangledNames.add(first.substring(0, 1).toLowerCase() + delim + middle.substring(0, 1).toLowerCase() + delim + last.toLowerCase() + domain);
                    if (caseSensitiveCheckBox.isSelected()) {
                        mangledNames.add(toMixedCase(first) + delim + toMixedCase(middle) + delim + toMixedCase(last) + domain);
                        mangledNames.add(first.substring(0, 1).toUpperCase() + delim + middle.substring(0, 1).toUpperCase() + delim + toMixedCase(last) + domain);
                    }
                }

                // Common numerics
                if (numericSuffixesCheckBox.isSelected()) {
                    for (int i = 0; i < 100; i++) {
                        addCommonNumeric(mangledNames, first.toLowerCase(), i);
                        addCommonNumeric(mangledNames, first.toLowerCase() + delim + last.toLowerCase(), i);
                        addCommonNumeric(mangledNames, first.substring(0, 1).toLowerCase() + delim + last.toLowerCase(), i);
                        addCommonNumeric(mangledNames, last.toLowerCase(), i);
                        addCommonNumeric(mangledNames, first.toLowerCase() + delim + last.substring(0, 1).toLowerCase(), i);

                        if (caseSensitiveCheckBox.isSelected()) {
                            addCommonNumeric(mangledNames, toMixedCase(first), i);
                            addCommonNumeric(mangledNames, first.substring(0, 1).toUpperCase() + delim + toMixedCase(last), i);
                            addCommonNumeric(mangledNames, toMixedCase(last), i);
                        }
                    }
                }
                // years
                if (yearSuffixesCheckBox.isSelected()) {
                    for (int i = 2000; i < thisYear + 1; i++) {
                        addCommonNumeric(mangledNames, first.toLowerCase(), i);
                        addCommonNumeric(mangledNames, first.toLowerCase() + delim + last.toLowerCase(), i);
                        addCommonNumeric(mangledNames, first.substring(0, 1).toLowerCase() + delim + last.toLowerCase(), i);
                        addCommonNumeric(mangledNames, last.toLowerCase(), i);
                        addCommonNumeric(mangledNames, first.toLowerCase() + delim + last.substring(0, 1).toLowerCase(), i);

                        if (caseSensitiveCheckBox.isSelected()) {
                            addCommonNumeric(mangledNames, toMixedCase(first), i);
                            addCommonNumeric(mangledNames, first.substring(0, 1).toUpperCase() + delim + toMixedCase(last), i);
                            addCommonNumeric(mangledNames, toMixedCase(last), i);
                        }
                    }
                }
            }

            private void addCommonNumeric(Set<String> mangledNames, String name, int numeric) {
                mangledNames.add(name + numeric);
                if (numeric < 10) {
                    mangledNames.add(name + "0" + numeric);
                }
            }

            private String toMixedCase(String input) {
                return input.substring(0, 1).toUpperCase() + input.substring(1).toLowerCase();
            }

            @Override
            protected void done() {
                super.done();
                try {
                    String results = (String) get();
                    outputText.setText(results);
                    //callbacks.printOutput("Results length set to output: " + results.length());
                } catch (InterruptedException e) {
                    callbacks.printError(e.toString());
                } catch (ExecutionException e) {
                    callbacks.printError(e.toString());
                }
            }
        };

        worker.execute();
    }

    @Override
    public Component getTabComponent() {
        return mainPanel;
    }

    @Override
    public String getTabTitle() {
        return "Name Mangler";
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
        mainPanel.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(2, 2, new Insets(5, 5, 5, 5), -1, -1));
        mainPanel.setMinimumSize(new Dimension(100, 100));
        mainPanel.setOpaque(true);
        mainPanel.setPreferredSize(new Dimension(100, 100));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel1, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, 1, null, null, null, 0, false));
        helpNameMangler = new JPanel();
        helpNameMangler.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(helpNameMangler, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        helpNameMangler.setBorder(BorderFactory.createTitledBorder(BorderFactory.createRaisedBevelBorder(), null));
        final JLabel label1 = new JLabel();
        label1.setIcon(new ImageIcon(getClass().getResource("/com/professionallyevil/co2/images/help.png")));
        label1.setText("");
        helpNameMangler.add(label1, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer1 = new com.intellij.uiDesigner.core.Spacer();
        panel1.add(spacer1, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 3, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel2, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_NORTH, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(-1, 500), null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(panel3, new com.intellij.uiDesigner.core.GridConstraints(0, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_NORTH, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(-1, 500), null, 0, false));
        panel3.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Output"));
        final JScrollPane scrollPane1 = new JScrollPane();
        panel3.add(scrollPane1, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        outputText = new JTextArea();
        outputText.setText("");
        scrollPane1.setViewportView(outputText);
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(panel4, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        mangleButton = new JButton();
        mangleButton.setText("Mangle Names");
        panel4.add(mangleButton, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(4, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel4.add(panel5, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel5.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Options"));
        caseSensitiveCheckBox = new JCheckBox();
        caseSensitiveCheckBox.setText("Case Sensitive");
        caseSensitiveCheckBox.setToolTipText("Include case variations (e.g. jsmith, JSmith)");
        panel5.add(caseSensitiveCheckBox, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        numericSuffixesCheckBox = new JCheckBox();
        numericSuffixesCheckBox.setText("Numeric Suffixes");
        numericSuffixesCheckBox.setToolTipText("Include common numeric suffixes (e.g. jsmith1, jsmith2)");
        panel5.add(numericSuffixesCheckBox, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        yearSuffixesCheckBox = new JCheckBox();
        yearSuffixesCheckBox.setText("Year Suffixes");
        yearSuffixesCheckBox.setToolTipText("Include year suffixes from 2000 on (e.g. jsmith2000, jsmith2014)");
        panel5.add(yearSuffixesCheckBox, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        delimitersText = new JTextField();
        delimitersText.setText("._-");
        delimitersText.setToolTipText("Delimiters to try between name parts (e.g. j.smith, j-smith)");
        panel5.add(delimitersText, new com.intellij.uiDesigner.core.GridConstraints(3, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Delimiters:");
        panel5.add(label2, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel6 = new JPanel();
        panel6.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(panel6, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_NORTH, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(-1, 500), null, 0, false));
        final JPanel panel7 = new JPanel();
        panel7.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel6.add(panel7, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        panel7.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Names"));
        final JScrollPane scrollPane2 = new JScrollPane();
        panel7.add(scrollPane2, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        inputText = new JTextArea();
        scrollPane2.setViewportView(inputText);
        final JPanel panel8 = new JPanel();
        panel8.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel6.add(panel8, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        panel8.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Domains"));
        final JScrollPane scrollPane3 = new JScrollPane();
        panel8.add(scrollPane3, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        domains = new JTextArea();
        scrollPane3.setViewportView(domains);
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return mainPanel;
    }
}
