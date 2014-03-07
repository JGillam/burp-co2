/**
 * NOTE: This file copied pretty much verbatim from the BurpHttpRequestWrapper.java file in burp-auth
 * (see https://github.com/dnet/burp-oauth).
 * Credit goes to Andras Veres-Szentkiralyi, who gracefully provides use of this code under the following
 * license:

 ----------------------------------------------------------------
 Copyright (c) 2013 Andras Veres-Szentkiralyi

 Permission is hereby granted, free of charge, to any person
 obtaining a copy of this software and associated documentation
 files (the "Software"), to deal in the Software without
 restriction, including without limitation the rights to use,
 copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following
 conditions:

 The above copyright notice and this permission notice shall be
 included in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.
 -----------------------------------------------------------------
 */

package com.professionallyevil.co2.oauth;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import oauth.signpost.http.HttpRequest;

import java.nio.charset.Charset;
import java.util.*;
import java.io.*;

public class SignpostBurpHttpRequestWrapper implements HttpRequest {

    private IHttpRequestResponse request;
    private static final Charset UTF_8 = Charset.forName("UTF-8");

    public SignpostBurpHttpRequestWrapper(IHttpRequestResponse request) {
        this.request = request;
    }

    public String getMethod() {
        StringBuilder method = new StringBuilder();
        for (byte b : request.getRequest()) {
            if (b == ' ') {
                break;
            } else {
                method.append((char) b);
            }
        }
        return method.toString();
    }

    public String getRequestUrl() {
        IHttpService hs = request.getHttpService();
        StringBuilder url = new StringBuilder();
        url.append(hs.getProtocol());
        url.append("://");
        url.append(hs.getHost());
        url.append(":");
        url.append(hs.getPort());
        boolean capture = false;
        for (byte b : request.getRequest()) {
            if (b == ' ') {
                if (capture) {
                    break;
                } else {
                    capture = true;
                }
            } else if (capture) {
                url.append((char) b);
            }
        }
        return url.toString();
    }

    public String getContentType() {
        return getHeader("Content-Type");
    }

    public String getHeader(String name) {
        return getAllHeaders().get(name);
    }

    public Map<String, String> getAllHeaders() {
        Map<String, String> retval = new HashMap<String, String>();
        byte state = 0; // 0 - first line, 1 - wait for \n, 2 - key, 3 - value
        StringBuilder key = null, value = null;
        byteloop:
        for (byte b : request.getRequest()) {
            switch (state) {
                case 0:
                    if (b == '\r') state = 1;
                    break;
                case 1:
                    if (b == '\n') {
                        state = 2;
                        key = new StringBuilder();
                    }
                    break;
                case 2:
                    if (b == ':') {
                        state = 3;
                        value = new StringBuilder();
                    } else if (b == '\r' || b == '\n') {
                        break byteloop;
                    } else {
                        key.append((char) b);
                    }
                    break;
                case 3:
                    if (b == '\r') {
                        state = 1;
                        retval.put(key.toString(), value.substring(1)); // starts with a space
                    } else {
                        value.append((char) b);
                    }
                    break;
            }
        }
        return retval;
    }

    public void setHeader(String name, String value) {
        byte state = 0; // 0 - first/wrong line, 1 - wait for \n, 2 - key, 3 - value, 4 - append, 5 - overwrite
        int namePos = 0, valueStart = 0, valueEnd = 0; // start - ':', end - '\r'
        final byte[] req = request.getRequest();
        for (int pos = 0; pos < req.length; pos++) {
            char b = (char) req[pos];
            switch (state) {
                case 0:
                    if (b == '\r') state = 1;
                    break;
                case 1:
                    if (b == '\n') {
                        state = 2;
                        namePos = 0;
                    }
                    break;
                case 2:
                    if (b == ':') {
                        state = 3;
                        valueStart = pos;
                    } else if (b == '\r' || b == '\n') {
                        state = 4;
                        valueStart = pos;
                    } else if (name.charAt(namePos) != b) {
                        state = 0;
                    } else {
                        namePos++;
                    }
                    break;
                case 3:
                    if (b == '\r') {
                        state = 5;
                        valueEnd = pos;
                    }
                    break;
            }
            if (state > 3) break;
        }
        byte[] updated;
        if (state == 5) {
            byte[] toInsert = value.getBytes(UTF_8);
            updated = new byte[req.length - (valueEnd - valueStart - 2) + toInsert.length];
            System.arraycopy(req, 0, updated, 0, valueStart + 2);
            System.arraycopy(toInsert, 0, updated, valueStart + 2, toInsert.length);
            System.arraycopy(req, valueEnd, updated, valueStart + 2 + toInsert.length,
                    req.length - valueEnd);
        } else {
            byte[] toInsert = String.format("%s: %s\r\n", name, value).getBytes(UTF_8);
            updated = new byte[req.length + toInsert.length];
            System.arraycopy(req, 0, updated, 0, valueStart);
            System.arraycopy(toInsert, 0, updated, valueStart, toInsert.length);
            System.arraycopy(req, valueStart, updated, valueStart + toInsert.length,
                    req.length - valueStart);
        }
        request.setRequest(updated);
    }

    public InputStream getMessagePayload() throws IOException {
        return null;
    }

    public IHttpRequestResponse unwrap() {
        return request;
    }

    public void setRequestUrl(String url) {
        throw new RuntimeException("SignpostBurpHttpRequestWrapper.setRequestUrl is not implemented");
    }
}
