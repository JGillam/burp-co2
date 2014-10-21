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


import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;

public class ActionCopyAll extends AbstractAction {
    DefaultListModel<String> listModel;
    ClipboardOwner clipboardOwner;

    public ActionCopyAll(DefaultListModel<String> listModel, ClipboardOwner tab) {
        super("Copy All");
        this.listModel = listModel;
        this.clipboardOwner = tab;
        //putValue(SHORT_DESCRIPTION, desc);
        //putValue(MNEMONIC_KEY, mnemonic);
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < listModel.getSize(); i++) {
            buf.append(listModel.get(i));
            buf.append("\n");
        }
        StringSelection contents = new StringSelection(buf.toString().trim());
        clipboard.setContents(contents, clipboardOwner);
    }
}
