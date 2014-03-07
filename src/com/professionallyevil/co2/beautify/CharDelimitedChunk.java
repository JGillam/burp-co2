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

package com.professionallyevil.co2.beautify;

import java.io.IOException;
import java.io.PushbackReader;
import java.util.Arrays;

public class CharDelimitedChunk extends Chunk{
    char endToken;
    String startToken;
    TextChunk text;

    public CharDelimitedChunk(String start, char end){
        this.startToken = start;
        this.endToken = end;
        this.text = new TextChunk();
    }

    @Override
    void process(PushbackReader r) throws IOException {
        char c = (char) r.read();
        boolean endReached = false;
        while (c != EOFChar && !endReached) {
            if (c == endToken) {
                endReached = true;
            } else {
                Chunk chunk = findChunk(c, r);
                if (chunk == null) {
                    text.append(c);
                } else {
                    addChunk(text);
                    addChunk(chunk);
                    text = new TextChunk();
                }
                c = (char) r.read();
            }
        }
        addChunk(text);
    }

    String toString(int indent){
        char[] indenter = new char[indent];
        Arrays.fill(indenter, ' ');
        StringBuilder buf = new StringBuilder();
        buf.append(indenter);
        buf.append(startToken);
        buf.append('\n');
        buf.append(super.toString(indent + 2));
        buf.append(indenter);
        buf.append(endToken);
        buf.append('\n');
        return buf.toString();
    }
}
