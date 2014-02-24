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

package com.secureideas.co2.cewler;


import burp.IHttpRequestResponse;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class BurpMessageListModel extends AbstractListModel<IHttpRequestResponse> {
    private List<IHttpRequestResponse> messages = new ArrayList<IHttpRequestResponse>();

    public void addMessages(List<IHttpRequestResponse> newMessages){
        int startSize = messages.size();
        messages.addAll(newMessages);
        fireIntervalAdded(this, startSize, messages.size());
    }

    public void clearMessages(){
        int startSize = messages.size();
        messages.clear();
        fireIntervalRemoved(this, 0, messages.size());
    }

    @Override
    public int getSize() {
        return messages.size();
    }

    @Override
    public IHttpRequestResponse getElementAt(int index) {
        return messages.get(index);
    }

    public List<IHttpRequestResponse> getMessages(){
        return messages;
    }
}
