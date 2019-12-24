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


import burp.IHttpRequestResponse;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

/**
 * ListModel for IHttpRequestResponse items.  Much like the default ListModel but backed with an ArrayList.
 */
public class BurpMessageListModel extends DefaultListModel<IHttpRequestResponse> {

    public void addMessages(List<IHttpRequestResponse> messages) {
        for (IHttpRequestResponse msg : messages) {
            addElement(msg);
        }
    }

    public IHttpRequestResponse[] getMessages() {
        List<IHttpRequestResponse> messagesList = new ArrayList<IHttpRequestResponse>(getSize());
        IHttpRequestResponse[] messages = new IHttpRequestResponse[getSize()];
        copyInto(messages);
        return messages;
    }
}
