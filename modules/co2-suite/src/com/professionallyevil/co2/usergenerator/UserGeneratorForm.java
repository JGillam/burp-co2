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

package com.professionallyevil.co2.usergenerator;

import burp.IBurpExtenderCallbacks;
import com.professionallyevil.co2.Co2HelpLink;
import com.professionallyevil.co2.StatItem;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutionException;

/**
 * User: jasong
 * Date: 2/6/14
 * Time: 8:06 PM
 */
public class UserGeneratorForm implements ClipboardOwner {
    private JPanel mainPanel;
    private JPanel outputPanel;
    private JSlider startSlider;
    private JLabel startFromLabel;
    private JSlider endSlider;
    private JLabel toTheLabel;
    private JTextArea outputListArea;
    private JButton addFirstNames;
    private JCheckBox firstNamesLowercaseChk;
    private JPanel firstNamesLowerChk;
    private JCheckBox firstNamesMixedcaseChk;
    private JCheckBox firstNamesUppercaseChk;
    private JSlider surnamePercentSlider;
    private JLabel surnameTopPercentLbl;
    private JCheckBox surnamesLowercaseChk;
    private JCheckBox surnameMixedcaseChk;
    private JCheckBox surnameUppercaseChk;
    private JButton addSurnames;
    private JCheckBox firstNameJustInitialChk;
    private JTextField combinerDelimiterTxt;
    private JCheckBox switchOrderCheckBox;
    private JButton addCombosButton;
    private JProgressBar progressBar;
    private JLabel statusLabel;
    private JCheckBox commonNicknamesCheckBox;
    private JLabel helpUserGenerator;
    private JLabel limitToLabel;
    private JTextField txtOutputLimit;
    private static final String RESOURCE_FOLDER = "com/professionallyevil/co2/lists/";
    private IBurpExtenderCallbacks callbacks;
    private int surnamesMax = 151671;
    private static final int MAX_COLLECTED = 200000; //TODO: make configurable
    private static final int MAX_PAYLOADS = 100000; //TODO: make configurable

    public UserGeneratorForm() {
        final JPopupMenu popup = new JPopupMenu();
        JMenuItem copy = new JMenuItem("Copy all");
        popup.add(copy);
        popup.setInvoker(outputListArea);
        copy.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                StringSelection contents = new StringSelection(outputListArea.getText());
                clipboard.setContents(contents, UserGeneratorForm.this);
            }
        });


        startSlider.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                if (startSlider.getValue() > endSlider.getValue()) {
                    endSlider.setValue(startSlider.getValue());
                }
                setupSliderLabel(startSlider, startFromLabel);
            }
        });
        endSlider.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                if (endSlider.getValue() < startSlider.getValue()) {
                    startSlider.setValue(endSlider.getValue());
                }
                setupSliderLabel(endSlider, toTheLabel);
            }
        });

        setupSliderLabel(startSlider, startFromLabel);
        setupSliderLabel(endSlider, toTheLabel);
        addFirstNames.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                statusLabel.setText("Reading first names...");
                progressBar.setIndeterminate(true);
                SwingWorker worker = new SwingWorker<TreeSet<StatItem>, Object>() {
                    @Override
                    protected TreeSet<StatItem> doInBackground() throws Exception {
                        HashMap<StatItem, Integer> stats = getFirstNamesMap();
                        TreeSet<StatItem> sortedItems = new TreeSet<StatItem>();
                        sortedItems.addAll(stats.keySet());
                        return sortedItems;
                    }

                    @Override
                    protected void done() {
                        super.done();
                        try {
                            TreeSet<StatItem> sortedItems = get();
                            statusLabel.setText("Result set size: " + sortedItems.size());
                            progressBar.setIndeterminate(false);
                            outputList(sortedItems);
                        } catch (InterruptedException e1) {
                            callbacks.printError(e1.toString());
                        } catch (ExecutionException e1) {
                            callbacks.printError(e1.toString());
                        }
                    }
                };
                worker.execute();
            }
        });

        surnamePercentSlider.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                setupSliderPercentLabel(surnamePercentSlider, surnameTopPercentLbl);
            }
        });

        setupSliderPercentLabel(surnamePercentSlider, surnameTopPercentLbl);
        addSurnames.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                statusLabel.setText("Reading surnames...");
                progressBar.setIndeterminate(true);
                SwingWorker<Set<StatItem>, Integer> worker = new SwingWorker<Set<StatItem>, Integer>() {
                    @Override
                    protected Set<StatItem> doInBackground() throws Exception {
                        HashMap<StatItem, Integer> stats = getSurnamesMap();
                        TreeSet<StatItem> sortedItems = new TreeSet<StatItem>();
                        sortedItems.addAll(stats.keySet());
                        return sortedItems;
                    }

                    @Override
                    protected void done() {
                        super.done();
                        try {
                            TreeSet<StatItem> sortedItems = (TreeSet<StatItem>) get();
                            statusLabel.setText("Result set size: " + sortedItems.size());
                            progressBar.setIndeterminate(false);
                            outputList(sortedItems);
                        } catch (InterruptedException e1) {
                            callbacks.printError(e1.toString());
                        } catch (ExecutionException e1) {
                            callbacks.printError(e1.toString());
                        }
                    }
                };
                worker.execute();

            }
        });

        firstNameJustInitialChk.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                if (firstNameJustInitialChk.isSelected()) {
                    firstNamesMixedcaseChk.setSelected(false);
                    commonNicknamesCheckBox.setSelected(false);
                    firstNamesMixedcaseChk.setEnabled(false);
                } else {
                    firstNamesMixedcaseChk.setEnabled(true);
                }
            }
        });

        addCombosButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                progressBar.setIndeterminate(true);
                SwingWorker worker = new SwingWorker<TreeSet<StatItem>, Object>() {
                    @Override
                    protected void process(List chunks) {
                        if (chunks.size() > 0) {
                            Integer i = (Integer) chunks.get(chunks.size() - 1);
                            progressBar.setValue(i);
                        }

                    }

                    @Override
                    protected TreeSet<StatItem> doInBackground() throws Exception {
                        progressBar.setIndeterminate(true);
                        statusLabel.setText("Getting first names...");
                        TreeSet<StatItem> firstNameStats = new TreeSet<StatItem>();
                        firstNameStats.addAll(getFirstNamesMap().keySet());

                        statusLabel.setText("Getting surnames...");
                        TreeSet<StatItem> surnameStats = new TreeSet<StatItem>();
                        surnameStats.addAll(getSurnamesMap().keySet());

                        String delimiter = combinerDelimiterTxt.getText();

                        int firstTopValue = 0;   // the top value from the first names
                        for (StatItem item : firstNameStats) {
                            firstTopValue = Math.max(firstTopValue, item.getValue());
                        }

                        int surTopValue = 0;
                        int surBottomValue = Integer.MAX_VALUE; // the bottom value from the surnames
                        for (StatItem item : surnameStats) {
                            surTopValue = Math.max(surTopValue, item.getValue());
                            surBottomValue = Math.min(surBottomValue, item.getValue());

                        }


                        //int basement = surnameStats.size() + firstNameStats.size() * 20 / 100;  // ignore any combos that are below the basement (the bottom 20%).

                        TreeSet<StatItem> outputSet = new TreeSet<StatItem>();
                        int i = 0;
                        statusLabel.setText("Processing combos...");
                        progressBar.setIndeterminate(false);

                        progressBar.setMaximum(Math.min(firstNameStats.size() * surnameStats.size(), MAX_COLLECTED));

                        int s = surnameStats.size();
                        for (StatItem surnameItem : surnameStats) {
                            int f = firstNameStats.size();
                            for (StatItem firstNameItem : firstNameStats) {
                                String comboName;
                                if (switchOrderCheckBox.isSelected()) {
                                    comboName = surnameItem.getName() + delimiter + firstNameItem.getName();
                                } else {
                                    comboName = firstNameItem.getName() + delimiter + surnameItem.getName();
                                }

                                int comboValue = f + s;  // this is a rough approximation to bubble up more likely names to the top of the list
                                //if(comboValue > basement){
                                outputSet.add(new StatItem(comboName, comboValue));
                                publish(i++);
                                //}

                                if (outputSet.size() >= MAX_COLLECTED) {   // shortcut for really long lists
                                    return outputSet;
                                }
                                f--;
                            }
                            s--;
                        }

                        return outputSet;
                    }

                    @Override
                    protected void done() {
                        super.done();
                        try {
                            TreeSet<StatItem> results = get();
                            progressBar.setValue(0);
                            statusLabel.setText("Payload list iterated through: " + results.size());
                            outputList(results);
                        } catch (InterruptedException e1) {
                            callbacks.printError(e1.toString());
                        } catch (ExecutionException e1) {
                            callbacks.printError(e1.toString());
                        }
                    }
                };
                worker.execute();

            }
        });
        commonNicknamesCheckBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (commonNicknamesCheckBox.isSelected()) {
                    firstNameJustInitialChk.setSelected(false);
                }
            }
        });
        helpUserGenerator.addMouseListener(new Co2HelpLink("http://co2.professionallyevil.com/help-usergen.php", helpUserGenerator));
    }

    // must be called from within a SwingWorker
    private HashMap<StatItem, Integer> getSurnamesMap() throws Exception {
        int percent = startSlider.getValue();
        int max = surnamesMax * percent / 100;
        HashMap<StatItem, Integer> stats = new HashMap<StatItem, Integer>(max);
        readListInto("surnames_census2000.csv", stats, max, surnamesLowercaseChk.isSelected(), surnameMixedcaseChk.isSelected(),
                surnameUppercaseChk.isSelected(), false, false);
        return stats;
    }

    // must be called from within a SwingWorker
    private HashMap<StatItem, Integer> getFirstNamesMap() throws Exception {
        int start = startSlider.getValue();
        int end = endSlider.getValue() + 1;
        HashMap<StatItem, Integer> stats = new HashMap<StatItem, Integer>(400);

        for (int i = start; i < end; i += 10) {
            readListInto("firstnames_" + (1900 + i) + "s.csv", stats, Integer.MAX_VALUE, firstNamesLowercaseChk.isSelected(),
                    firstNamesMixedcaseChk.isSelected(), firstNamesUppercaseChk.isSelected(), firstNameJustInitialChk.isSelected(), true);
        }
        return stats;
    }


    private void outputList(TreeSet<StatItem> sortedItems) {
        StringBuilder payloadList = new StringBuilder();
        Iterator<StatItem> itemIterator = sortedItems.iterator();
        int limit = limit();
        for (int i = 0; itemIterator.hasNext() && i < limit; i++) {
            StatItem item = itemIterator.next();
            payloadList.append(item);//.append(": ").append(item.getValue());               //TODO: output to file?
            payloadList.append("\n");
        }
        payloadList.deleteCharAt(payloadList.length() - 1); // remove last \n
        outputListArea.setText(payloadList.toString());
    }

    private void setupSliderPercentLabel(JSlider slider, JLabel label) {
        int value = slider.getValue();

        label.setText(String.valueOf(value) + "% (about " + (value * surnamesMax / 100) + ")");
    }

    private void setupSliderLabel(JSlider slider, JLabel label) {
        int value = slider.getValue();
        label.setText(String.valueOf(1900 + value) + "s");
    }

    //TODO: fix issue - processes nicknames even for surnames
    private int readListInto(String resourceName, Map<StatItem, Integer> itemSet, int maxCount, boolean lowercase, boolean mixedcase, boolean uppercase, boolean justInitial, boolean includeNicknames) throws Exception {
        InputStream inStream = UserGeneratorForm.this.getClass().getClassLoader().getResourceAsStream(RESOURCE_FOLDER + resourceName);
        BufferedReader reader = new BufferedReader(new InputStreamReader(inStream));

        String line = reader.readLine();
        int i = 0;

        HashMap<String, String[]> nicknameMap;
        if (includeNicknames) {
            nicknameMap = getNicknames(); // will only be populated if checkbox is selected.
        } else {
            nicknameMap = new HashMap<String, String[]>();
        }

        while (line != null && i < maxCount) {
            String[] strings = line.split(",");
            String[] nicknames = nicknameMap.get(strings[0].toLowerCase());
            if (strings.length == 2) {
                int value = Integer.parseInt(strings[1]);

                if (justInitial) {
                    if (lowercase) {
                        StatItem item = new StatItem(strings[0].substring(0, 1).toLowerCase(), value);
                        addOrUpdateStat(itemSet, item);
                    }
                    if (uppercase) {
                        StatItem item = new StatItem(strings[0].substring(0, 1).toUpperCase(), value);
                        addOrUpdateStat(itemSet, item);
                    }

                } else {

                    if (lowercase) {
                        StatItem item = new StatItem(strings[0].toLowerCase(), value);
                        addOrUpdateStat(itemSet, item);
                        if (nicknames != null && nicknames.length > 0) {
                            for (String nick : nicknames) {
                                StatItem nickItem = new StatItem(nick.toLowerCase(), value);
                                addOrUpdateStat(itemSet, nickItem);
                            }
                        }
                    }

                    if (uppercase) {
                        StatItem item = new StatItem(strings[0].toUpperCase(), value);
                        addOrUpdateStat(itemSet, item);
                        if (nicknames != null && nicknames.length > 0) {
                            for (String nick : nicknames) {
                                StatItem nickItem = new StatItem(nick.toUpperCase(), value);
                                addOrUpdateStat(itemSet, nickItem);
                            }
                        }
                    }

                    if (mixedcase) {
                        StatItem item = new StatItem(strings[0].substring(0, 1).toUpperCase() + strings[0].substring(1).toLowerCase(), value);
                        addOrUpdateStat(itemSet, item);
                        if (nicknames != null && nicknames.length > 0) {
                            for (String nick : nicknames) {
                                StatItem nickItem = new StatItem(nick.substring(0, 1).toUpperCase() + nick.substring(1).toLowerCase(), value);
                                addOrUpdateStat(itemSet, nickItem);
                            }
                        }
                    }
                }
            }
            i++;
            line = reader.readLine();
        }

        inStream.close();
        return i;
    }

    private HashMap<String, String[]> getNicknames() {
        HashMap<String, String[]> nicknames = new HashMap<String, String[]>();
        if (commonNicknamesCheckBox.isSelected()) {
            InputStream inStream = UserGeneratorForm.this.getClass().getClassLoader().getResourceAsStream(RESOURCE_FOLDER + "nicknames.csv");
            BufferedReader reader = new BufferedReader(new InputStreamReader(inStream));

            try {
                String line = reader.readLine();
                while (line != null) {
                    String[] values = line.split(",");
                    if (values.length > 1) {
                        nicknames.put(values[0], Arrays.copyOfRange(values, 1, values.length));
                    }

                    line = reader.readLine();
                }

                inStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return nicknames;

    }

    private void addOrUpdateStat(Map<StatItem, Integer> itemSet, StatItem item) {
        Integer oldValue = itemSet.get(item);
        if (oldValue != null) {
            item.addValue(oldValue);
            itemSet.remove(item);
        }
        itemSet.put(item, item.getValue());
    }

    public JPanel getMainPanel() {
        return mainPanel;
    }

    public void setCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public void lostOwnership(Clipboard clipboard, Transferable contents) {

    }

    private int limit() {
        try {
            return Integer.parseInt(txtOutputLimit.getText());
        } catch (NumberFormatException e) {
            return 10000;
        }

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
        mainPanel.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(5, 3, new Insets(5, 5, 5, 5), -1, -1));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(5, 2, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel1, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 2, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer1 = new com.intellij.uiDesigner.core.Spacer();
        panel1.add(spacer1, new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(5, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel2, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 5, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        firstNamesLowerChk = new JPanel();
        firstNamesLowerChk.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(8, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(firstNamesLowerChk, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 3, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        firstNamesLowerChk.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "First Names"));
        final com.intellij.uiDesigner.core.Spacer spacer2 = new com.intellij.uiDesigner.core.Spacer();
        firstNamesLowerChk.add(spacer2, new com.intellij.uiDesigner.core.GridConstraints(7, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        startSlider = new JSlider();
        startSlider.setMajorTickSpacing(10);
        startSlider.setMaximum(100);
        startSlider.setMinimum(20);
        startSlider.setPaintLabels(false);
        startSlider.setPaintTicks(true);
        startSlider.setSnapToTicks(true);
        startSlider.setValue(50);
        startSlider.putClientProperty("JSlider.isFilled", Boolean.FALSE);
        firstNamesLowerChk.add(startSlider, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setText("From the:");
        firstNamesLowerChk.add(label1, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        startFromLabel = new JLabel();
        startFromLabel.setText("Label");
        firstNamesLowerChk.add(startFromLabel, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        endSlider = new JSlider();
        endSlider.setMajorTickSpacing(10);
        endSlider.setMinimum(20);
        endSlider.setPaintLabels(false);
        endSlider.setPaintTicks(true);
        endSlider.setSnapToTicks(true);
        endSlider.setValue(90);
        firstNamesLowerChk.add(endSlider, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("To the:");
        firstNamesLowerChk.add(label2, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        toTheLabel = new JLabel();
        toTheLabel.setText("Label");
        firstNamesLowerChk.add(toTheLabel, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        firstNamesLowercaseChk = new JCheckBox();
        firstNamesLowercaseChk.setSelected(true);
        firstNamesLowercaseChk.setText("Lowercase");
        firstNamesLowerChk.add(firstNamesLowercaseChk, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        firstNamesMixedcaseChk = new JCheckBox();
        firstNamesMixedcaseChk.setText("Mixedcase");
        firstNamesLowerChk.add(firstNamesMixedcaseChk, new com.intellij.uiDesigner.core.GridConstraints(5, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        firstNamesUppercaseChk = new JCheckBox();
        firstNamesUppercaseChk.setText("Uppercase");
        firstNamesLowerChk.add(firstNamesUppercaseChk, new com.intellij.uiDesigner.core.GridConstraints(6, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        firstNameJustInitialChk = new JCheckBox();
        firstNameJustInitialChk.setSelected(true);
        firstNameJustInitialChk.setText("Just Initial");
        firstNamesLowerChk.add(firstNameJustInitialChk, new com.intellij.uiDesigner.core.GridConstraints(4, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        commonNicknamesCheckBox = new JCheckBox();
        commonNicknamesCheckBox.setSelected(false);
        commonNicknamesCheckBox.setText("+Common Nicknames");
        firstNamesLowerChk.add(commonNicknamesCheckBox, new com.intellij.uiDesigner.core.GridConstraints(5, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(6, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel2.add(panel3, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 2, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel3.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Surnames"));
        final com.intellij.uiDesigner.core.Spacer spacer3 = new com.intellij.uiDesigner.core.Spacer();
        panel3.add(spacer3, new com.intellij.uiDesigner.core.GridConstraints(5, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        surnamePercentSlider = new JSlider();
        surnamePercentSlider.setMajorTickSpacing(5);
        surnamePercentSlider.setMinimum(5);
        surnamePercentSlider.setPaintTicks(true);
        surnamePercentSlider.setValue(20);
        panel3.add(surnamePercentSlider, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 2, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("Use the top:");
        panel3.add(label3, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        surnameTopPercentLbl = new JLabel();
        surnameTopPercentLbl.setText("Label");
        panel3.add(surnameTopPercentLbl, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        surnamesLowercaseChk = new JCheckBox();
        surnamesLowercaseChk.setSelected(true);
        surnamesLowercaseChk.setText("Lowercase");
        panel3.add(surnamesLowercaseChk, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        surnameMixedcaseChk = new JCheckBox();
        surnameMixedcaseChk.setText("Mixedcase");
        panel3.add(surnameMixedcaseChk, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        surnameUppercaseChk = new JCheckBox();
        surnameUppercaseChk.setText("Uppercase");
        panel3.add(surnameUppercaseChk, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        addFirstNames = new JButton();
        addFirstNames.setText("Just Add First Names");
        addFirstNames.setToolTipText("Add first names to the payload list");
        panel1.add(addFirstNames, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        addSurnames = new JButton();
        addSurnames.setText("Just Add Surnames");
        panel1.add(addSurnames, new com.intellij.uiDesigner.core.GridConstraints(4, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer4 = new com.intellij.uiDesigner.core.Spacer();
        panel1.add(spacer4, new com.intellij.uiDesigner.core.GridConstraints(3, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(3, 4, new Insets(0, 0, 0, 0), -1, -1));
        panel1.add(panel4, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel4.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Combine First names and Surnames"));
        combinerDelimiterTxt = new JTextField();
        panel4.add(combinerDelimiterTxt, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("Delimiter:");
        panel4.add(label4, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        switchOrderCheckBox = new JCheckBox();
        switchOrderCheckBox.setText("Switch Order");
        panel4.add(switchOrderCheckBox, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        addCombosButton = new JButton();
        addCombosButton.setText("Add Combos");
        panel4.add(addCombosButton, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 4, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        outputPanel = new JPanel();
        outputPanel.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(outputPanel, new com.intellij.uiDesigner.core.GridConstraints(1, 2, 2, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        outputPanel.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Output"));
        final JScrollPane scrollPane1 = new JScrollPane();
        outputPanel.add(scrollPane1, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        outputListArea = new JTextArea();
        outputListArea.setText("");
        scrollPane1.setViewportView(outputListArea);
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        outputPanel.add(panel5, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        limitToLabel = new JLabel();
        limitToLabel.setText("Limit to: ");
        panel5.add(limitToLabel, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtOutputLimit = new JTextField();
        txtOutputLimit.setHorizontalAlignment(4);
        txtOutputLimit.setText("10000");
        txtOutputLimit.setToolTipText("Output no more than this number of results.");
        panel5.add(txtOutputLimit, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JPanel panel6 = new JPanel();
        panel6.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(2, 1, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel6, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 3, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel6.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Status"));
        progressBar = new JProgressBar();
        panel6.add(progressBar, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        statusLabel = new JLabel();
        statusLabel.setText(" ");
        panel6.add(statusLabel, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel7 = new JPanel();
        panel7.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel7, new com.intellij.uiDesigner.core.GridConstraints(0, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, 1, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer5 = new com.intellij.uiDesigner.core.Spacer();
        panel7.add(spacer5, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JPanel panel8 = new JPanel();
        panel8.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel7.add(panel8, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, 1, null, null, null, 0, false));
        panel8.setBorder(BorderFactory.createTitledBorder(BorderFactory.createRaisedBevelBorder(), null));
        helpUserGenerator = new JLabel();
        helpUserGenerator.setIcon(new ImageIcon(getClass().getResource("/com/professionallyevil/co2/images/help.png")));
        helpUserGenerator.setText("");
        panel8.add(helpUserGenerator, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer6 = new com.intellij.uiDesigner.core.Spacer();
        mainPanel.add(spacer6, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return mainPanel;
    }
}
