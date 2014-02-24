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


import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import com.secureideas.co2.StatusBar;

import javax.swing.*;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.parser.ParserDelegator;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class parses the HTML in all the supplied messages for all text and comments and generates a set of words which
 * are sent to the supplied listener.  Note that this class is invoked as a SwingWorker so it is safe to use even when parsing
 * and word extraction will take some time.  Words are stored in a Set to eliminate duplicates.
 */
public class WordExtractorWorker extends SwingWorker<Set<String>, Object> {
    private IBurpExtenderCallbacks callbacks;
    private List<IHttpRequestResponse> messages;
    private WordExtractorListener listener;
    private StatusBar statusBar;
    private boolean forceLowercase;
    private Pattern wordPattern = Pattern.compile("[a-zA-Z0-9]*");

    public WordExtractorWorker(IBurpExtenderCallbacks callbacks, StatusBar statusBar, List<IHttpRequestResponse> messages, boolean forceLowercase, WordExtractorListener l) {
        this.callbacks = callbacks;
        this.statusBar = statusBar;
        this.messages = messages;
        this.forceLowercase = forceLowercase;
        this.listener = l;
    }

    @Override
    protected Set<String> doInBackground() throws Exception {
        ParserDelegator parser = new ParserDelegator();
        final Set<String> words = new TreeSet<String>();

        HTMLEditorKit.ParserCallback parserCallback = new HTMLEditorKit.ParserCallback() {
            @Override
            public void handleComment(char[] data, int pos) {
                super.handleComment(data, pos);
                extractWords(data);
            }

            @Override
            public void handleText(char[] data, int pos) {
                super.handleText(data, pos);
                extractWords(data);
            }

            private void extractWords(char[] data) {
                String phrase = new String(data);
                Matcher m = wordPattern.matcher(phrase);
                while (m.find()) {
                    if (forceLowercase) {
                        words.add(m.group().toLowerCase());
                    } else {
                        words.add(m.group());
                    }
                }
            }
        };

        for (IHttpRequestResponse message : messages) {
            byte[] responseBytes = message.getResponse();
            IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(responseBytes);
            byte[] responseBody = Arrays.copyOfRange(responseBytes, responseInfo.getBodyOffset(), responseBytes.length);
            InputStreamReader reader = new InputStreamReader(new ByteArrayInputStream(responseBody));
            try {
                parser.parse(reader, parserCallback, true);
            } catch (IOException e1) {
                callbacks.printError("Could not parse HTML file " + e1.toString());

            }
        }
        return words;
    }

    @Override
    protected void done() {
        super.done();
        try {
            statusBar.setStatusText("Done.");
            Set<String> words = get();
            listener.addWords(words);
        } catch (InterruptedException e) {
            callbacks.printError(e.toString());
        } catch (ExecutionException e) {
            callbacks.printError(e.toString());
        }
    }
}
