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

import burp.IBurpExtenderCallbacks;
import com.professionallyevil.co2.Co2Configurable;
import com.professionallyevil.co2.Co2Extender;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import javax.swing.plaf.BorderUIResource;
import java.awt.*;
import java.awt.event.*;
import java.util.HashMap;

public class MasherConfig implements Co2Configurable {
    private JPanel mainPanel;
    private JPanel tabContainer;
    private JButton addTabButton;
    private JTabbedPane tabbedPane;
    private IBurpExtenderCallbacks callbacks;

    private int counter = 0;
    private HashMap<JButton, MasherTab> tabs = new HashMap<JButton, MasherTab>();

    public MasherConfig(final Co2Extender extender) {
        this.callbacks = extender.getCallbacks();

        addTabButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                addMasherTab();
            }
        });

        //TODO: add a clone tab button
    }

    private void addMasherTab() {
        final JLabel closeButton = new JLabel("x");
        closeButton.setOpaque(false);
        closeButton.setFocusable(false);
        closeButton.setForeground(Color.gray);
        final LineBorder blackBorder = new LineBorder(Color.black);
        final Border invisibleBorder = new BorderUIResource.EmptyBorderUIResource(1,1,1,1);
        closeButton.setBorder(invisibleBorder);
        closeButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                closeButton.setBorder(blackBorder);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                closeButton.setBorder(invisibleBorder);
            }
        });


        JPanel panel = new JPanel(new BorderLayout());
        panel.setOpaque(false);
        String labelText = "" + (counter++) + "  ";
        JLabel label = new JLabel(labelText);
        label.setOpaque(false);
        panel.add(label, BorderLayout.CENTER);
        //panel.add(closeButton, BorderLayout.EAST);   // TODO add the close tab functionality

        MasherTab masherTab = new MasherTab();
        tabbedPane.addTab(null, masherTab.getMainPanel());
        int index = tabbedPane.indexOfComponent(masherTab.getMainPanel());
        tabbedPane.setTabComponentAt(index, panel);

        //TODO: make the close button hide or close the tab
    }

    @Override
    public Component getTabComponent() {
        return mainPanel;
    }

    @Override
    public String getTabTitle() {
        return "Masher";
    }
}
