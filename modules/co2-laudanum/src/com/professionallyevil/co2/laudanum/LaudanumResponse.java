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
import burp.IResponseInfo;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class LaudanumResponse {

    private Map<String, String> params = new HashMap<String, String>();

    public LaudanumResponse(IBurpExtenderCallbacks callbacks, byte[] responseBytes) {
        IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(responseBytes);
        byte[] body = Arrays.copyOfRange(responseBytes, responseInfo.getBodyOffset(), responseBytes.length);

        String[] outputParts = callbacks.getHelpers().bytesToString(body).split("&");

        for (String part : outputParts) {
            String[] split = part.split("=");
            if (split.length == 2) {
                params.put(split[0].trim(), callbacks.getHelpers().urlDecode(split[1]));
                //callbacks.printOutput("Setting: " + part);
                //callbacks.printOutput("*** NAME = '" + split[0] + "'");
                //callbacks.printOutput("*** VALUE = "+split[1]);
                //callbacks.printOutput("*** DECODED VALUE = "+callbacks.getHelpers().urlDecode(split[1]));
            }
        }

        if (params.size() < 2) {
            params.put("stderr", callbacks.getHelpers().urlDecode(callbacks.getHelpers().bytesToString(body)));  // if we can't process the response, spit out what we got.
        }
    }

    public String getStderr() {
        return params.containsKey("stderr") ? params.get("stderr") : "";
    }

    public String getStdout() {
        return params.containsKey("stdout") ? params.get("stdout") : "";
    }

    public String getCwd() {
        return params.containsKey("cwd") ? params.get("cwd").trim() : "";
    }

}
