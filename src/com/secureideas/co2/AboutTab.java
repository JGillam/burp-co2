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

package com.secureideas.co2;

import javax.swing.*;

/**
 * User: jasong
 * Date: 2/7/14
 * Time: 5:43 PM
 */
public class AboutTab {


    private JPanel mainPanel;
    private JLabel textLabel;

    public JPanel getMainPanel() {
        return mainPanel;
    }

    public void setText(String text) {
        this.textLabel.setText(text);
    }
}
