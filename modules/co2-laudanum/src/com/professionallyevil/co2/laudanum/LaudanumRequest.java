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

package com.professionallyevil.co2.laudanum;

import burp.IBurpExtenderCallbacks;
import burp.IParameter;

import java.net.URL;

public class LaudanumRequest {
    private byte defaultParamType;
    private IBurpExtenderCallbacks callbacks;
    private byte[] requestBytes;


    public LaudanumRequest(IBurpExtenderCallbacks callbacks, URL url, String method) {
        this.callbacks = callbacks;

        if (method.equalsIgnoreCase("POST")) {
            defaultParamType = IParameter.PARAM_BODY;
        } else {
            defaultParamType = IParameter.PARAM_URL;
        }

        requestBytes = callbacks.getHelpers().buildHttpRequest(url);
    }

    private void addParameter(String name, String value, byte type) {
        IParameter param = callbacks.getHelpers().buildParameter(name, value, type);
        requestBytes = callbacks.getHelpers().addParameter(requestBytes, param);
    }

//    public void addPostParameter(String name, String value){
//        addParameter(name, value, IParameter.PARAM_BODY);
//    }

    public void setToken(String token) {
        addParameter("laudtoken", token, defaultParamType);
    }

    public void setCommand(String command) {
        addParameter("laudcmd", callbacks.getHelpers().urlEncode(command), defaultParamType);
    }

    public void setWorkingDirectory(String cwd) {
        addParameter("laudcwd", callbacks.getHelpers().urlEncode(cwd), defaultParamType);
    }

    public byte[] getRequestBytes() {
        return requestBytes;
    }

}
