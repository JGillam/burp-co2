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

package com.professionallyevil.co2.masher;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;


public class MasherTab {
    private JPanel mainPanel;
    private JTextArea inputList;
    private JSlider minCharsSlider;
    private JLabel minimumCharsLbl;
    private JLabel maximumCharsLbl;
    private JSlider maxCharsSlider;
    private JSpinner uppercaseSpinner;
    private JSpinner lowercaseSpinner;
    private JSpinner numericSpinner;
    private JSpinner specialSpinner;
    private JCheckBox restrictSpecialsCheckBox;
    private JTextField specialsText;
    private JCheckBox spacesOKCheckBox;
    private JTextField generatorName;
    private JButton createButton;


    public MasherTab() {
        minimumCharsLbl.setText(""+minCharsSlider.getValue());
        maximumCharsLbl.setText(""+maxCharsSlider.getValue());

        minCharsSlider.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                int value = minCharsSlider.getValue();
                minimumCharsLbl.setText(""+minCharsSlider.getValue());
                if(value > maxCharsSlider.getValue()){
                    maxCharsSlider.setValue(value);
                    maximumCharsLbl.setText(""+maxCharsSlider.getValue());
                }

            }
        });
        maxCharsSlider.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                int value = maxCharsSlider.getValue();
                maximumCharsLbl.setText(""+maxCharsSlider.getValue());
                if(value < minCharsSlider.getValue()){
                    minCharsSlider.setValue(value);
                    minimumCharsLbl.setText(""+minCharsSlider.getValue());
                }
            }
        });
        restrictSpecialsCheckBox.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                specialsText.setEnabled(restrictSpecialsCheckBox.isSelected());
                specialsText.setEditable(restrictSpecialsCheckBox.isSelected());
            }
        });
        createButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                inputList.setEnabled(false);
                inputList.setEditable(false);
                minCharsSlider.setEnabled(false);
                maxCharsSlider.setEnabled(false);
                uppercaseSpinner.setEnabled(false);
                lowercaseSpinner.setEnabled(false);
                numericSpinner.setEnabled(false);
                specialSpinner.setEnabled(false);
                restrictSpecialsCheckBox.setEnabled(false);
                spacesOKCheckBox.setEnabled(false);
                specialsText.setEnabled(false);
                specialsText.setEditable(false);
                generatorName.setEnabled(false);
                generatorName.setEditable(false);
                createButton.setEnabled(false);

                //TODO: create generator
            }
        });
    }

    public JPanel getMainPanel(){
       return mainPanel;
   }

    public void setGeneratorName(String name){
        generatorName.setText(name);
    }
}
