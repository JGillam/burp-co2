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
import java.awt.event.ActionEvent;

public class ActionRemoveSelected extends AbstractAction {
    JList list;
    DefaultListModel listModel;


    public ActionRemoveSelected(JList list, DefaultListModel listModel){
        super("Remove");
        this.list = list;
        this.listModel = listModel;
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        java.util.List selectedList = list.getSelectedValuesList();
        for(Object selectedItem:selectedList){
            listModel.removeElement(selectedItem);
        }
    }
}
