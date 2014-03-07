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
public class UserGeneratorForm implements ClipboardOwner{
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
    private static final String RESOURCE_FOLDER = "com/professionallyevil/co2/lists/";
    private IBurpExtenderCallbacks callbacks;
    private int surnamesMax = 151671;
    private static final int MAX_COLLECTED = 200000; //TODO: make configurable
    private static final int MAX_PAYLOADS = 100000; //TODO: make configurable

    public UserGeneratorForm(){
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
                SwingWorker worker = new SwingWorker<TreeSet<StatItem>,Object>() {
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
                SwingWorker<Set<StatItem>, Integer> worker = new SwingWorker<Set<StatItem>,Integer>() {
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
                SwingWorker worker = new SwingWorker<TreeSet<StatItem>,Object>() {
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
    }

    // must be called from within a SwingWorker
    private HashMap<StatItem, Integer> getSurnamesMap() throws Exception {
        int percent = startSlider.getValue();
        int max = surnamesMax * percent / 100;
        HashMap<StatItem, Integer> stats = new HashMap<StatItem, Integer>(max);
        readListInto("surnames_census2000.csv", stats, max, surnamesLowercaseChk.isSelected(), surnameMixedcaseChk.isSelected(),
                surnameUppercaseChk.isSelected(), false);
        return stats;
    }

    // must be called from within a SwingWorker
    private HashMap<StatItem, Integer> getFirstNamesMap() throws Exception {
        int start = startSlider.getValue();
        int end = endSlider.getValue() + 1;
        HashMap<StatItem, Integer> stats = new HashMap<StatItem, Integer>(400);

        for (int i = start; i < end; i += 10) {
            readListInto("firstnames_" + (1900 + i) + "s.csv", stats, Integer.MAX_VALUE, firstNamesLowercaseChk.isSelected(),
                    firstNamesMixedcaseChk.isSelected(), firstNamesUppercaseChk.isSelected(), firstNameJustInitialChk.isSelected());
        }
        return stats;
    }


    private void outputList(TreeSet<StatItem> sortedItems) {
        StringBuilder payloadList = new StringBuilder();
        Iterator<StatItem> itemIterator = sortedItems.iterator();
        for (int i = 0; itemIterator.hasNext(); i++) {
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
    private int readListInto(String resourceName, Map<StatItem, Integer> itemSet, int maxCount, boolean lowercase, boolean mixedcase, boolean uppercase, boolean justInitial) throws Exception {
        InputStream inStream = UserGeneratorForm.this.getClass().getClassLoader().getResourceAsStream(RESOURCE_FOLDER + resourceName);
        BufferedReader reader = new BufferedReader(new InputStreamReader(inStream));

        String line = reader.readLine();
        int i = 0;

        HashMap<String, String[]> nicknameMap = getNicknames(); // will only be populated if checkbox is selected.

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
}
