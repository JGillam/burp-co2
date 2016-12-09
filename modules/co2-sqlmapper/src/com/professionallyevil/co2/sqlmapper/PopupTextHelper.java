/*
 * Copyright (c) 2016 Jason Gillam
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

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

public class PopupTextHelper extends JPopupMenu implements MouseListener {

    JTextField target;

    PopupTextHelper(String[] options, JTextField target) {
        this.target = target;
        for (String option : options) {
            add(new PopupTextAction(option));

        }
        setInvoker(target);
        target.addMouseListener(this);
    }

    private void showPopup(MouseEvent e) {
        show(e.getComponent(), e.getX(), e.getY());
    }

    @Override
    public void mouseClicked(MouseEvent e) {

    }

    @Override
    public void mousePressed(MouseEvent e) {
        if (e.isPopupTrigger()) {
            showPopup(e);
        }
    }

    @Override
    public void mouseReleased(MouseEvent e) {
        if (e.isPopupTrigger()) {
            showPopup(e);
        }
    }

    @Override
    public void mouseEntered(MouseEvent e) {

    }

    @Override
    public void mouseExited(MouseEvent e) {

    }

    class PopupTextAction extends AbstractAction {

        PopupTextAction(String name) {
            this.putValue(Action.NAME, name);
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            PopupTextHelper.this.target.setText((String) this.getValue(Action.NAME));
        }
    }
}



