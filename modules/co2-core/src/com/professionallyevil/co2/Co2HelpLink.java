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

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.IOException;
import java.net.URI;

public class Co2HelpLink implements MouseListener {

    String link;
    JComponent sourceComponent;


    public Co2HelpLink(String link, JComponent source) {
        setLink(link);
        sourceComponent = source;
    }

    public void setLink
            (String link) {
        this.link = link;
    }

    @Override
    public void mouseClicked(MouseEvent e) {
        click();
    }

    @Override
    public void mousePressed(MouseEvent e) {

    }

    @Override
    public void mouseReleased(MouseEvent e) {

    }

    @Override
    public void mouseEntered(MouseEvent e) {

    }

    @Override
    public void mouseExited(MouseEvent e) {

    }

    private void click() {
        URI uri = null;
        if (link != null && !link.isEmpty()) {
            uri = URI.create(link);
        }

        if (uri != null && Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
            try {
                Desktop.getDesktop().browse(uri);
            } catch (IOException e) {
                //e.printStackTrace();
                popupAlternate(uri);
            }
        } else {
            popupAlternate(uri);
        }

    }

    private void popupAlternate(URI uri) {
        JOptionPane.showMessageDialog(sourceComponent.getTopLevelAncestor(), "Please visit co2.professionallyevil.com for assistance");

    }
}
