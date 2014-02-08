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

package com.secureideas.co2.beautify;

import java.io.IOException;
import java.io.PushbackReader;
import java.util.Arrays;
import java.util.StringTokenizer;

public class TextChunk extends Chunk {
    StringBuilder builder;

    TextChunk() {
        builder = new StringBuilder();
    }

    TextChunk(String s) {
        builder = new StringBuilder(s);
    }

    TextChunk(char c) {
        builder = new StringBuilder(c);
    }

    void append(String s) {
        builder.append(s);
    }

    void append(char c) {
        builder.append(c);
    }

    @Override
    void process(PushbackReader r) throws IOException {

    }

    @Override
    public String toString() {
        return builder.toString();
    }

    private String parseSemiColons(String text, int indentSize) {
        char[] indent = new char[indentSize];
        Arrays.fill(indent, ' ');

        StringBuilder results = new StringBuilder();
        for (StringTokenizer tokenizer = new StringTokenizer(text, ";"); tokenizer.hasMoreElements(); ) {
            String nextElement = ((String) tokenizer.nextElement()).trim();
            if (nextElement.length() > 0) {
                results.append(indent);
                results.append(nextElement.trim());
                results.append(';');
                results.append('\n');
            }
        }
        return results.toString();
    }

    String toString(int indent) {
        return parseSemiColons(builder.toString().trim(), indent);
    }
}
