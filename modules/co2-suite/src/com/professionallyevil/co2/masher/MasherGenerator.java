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

package com.professionallyevil.co2.masher;

import burp.IIntruderPayloadGenerator;

import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

public class MasherGenerator implements IIntruderPayloadGenerator, Runnable {
    private static final int BUFFER_SIZE = 3;
    private static final int FINAL_TIMEOUT = 20; // seconds
    private static final String[] COMMON_SUFFIXES = {"1", "123", "0", "111", "!"};
    private String name;
    private List<String[]> words;
    private PasswordSpec spec;
    private Thread generatorThread = null;
    private BlockingQueue<byte[]> queue = new ArrayBlockingQueue<byte[]>(BUFFER_SIZE);
    private byte[] lastPayload = new byte[0];

    public MasherGenerator(String name, Collection<String> input, PasswordSpec spec) {
        this.name = name;

        this.words = new ArrayList<String[]>(input.size());
        for (String word : input) {
            String[] w = new String[1];
            w[0] = word.toLowerCase();
            words.add(w);
        }
        this.spec = spec;

        generatorThread = new Thread(this, name);
        generatorThread.start();
    }

    @Override
    public boolean hasMorePayloads() {
        return !queue.isEmpty() || generatorThread.isAlive();
    }

    @Override
    public byte[] getNextPayload(byte[] baseValue) {
        byte[] nextPayload = null;
        try {
            nextPayload = queue.poll(FINAL_TIMEOUT, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            //e.printStackTrace();
        }
        if (nextPayload != null) {
            lastPayload = nextPayload;
        }

        return lastPayload;
    }

    @Override
    public void reset() {
        if (generatorThread != null && generatorThread.isAlive()) {
            generatorThread.interrupt();
        }

        queue.clear();

        generatorThread = new Thread(this, name);
        generatorThread.start();
    }

    @Override
    public void run() {
        try {
            List<String[]> combos = makeWordCombos();
            if (spec.isLowercaseOK()) {   // we do these first because if the spec allows them, they should be more common
                addLowercaseWords(words, "");
                addLowercaseWords(combos, "");
            }
            addMixedcaseWords(words, "");
            addMixedcaseWords(combos, "");

            addMostCommonSuffixes(words);
            addMostCommonSuffixes(combos);

            addCommon1337Variants(words);
            addCommon1337Variants(combos);

            addDateSuffixes(words);
            addDateSuffixes(combos);

            addPhrases(combos);

            addLessCommon1337Variants(words);
            addLessCommon1337Variants(combos);

            doubleUp1337Variants(words);
            doubleUp1337Variants(combos);
        } catch (InterruptedException e) {
            //e.printStackTrace(); Expected on a reset()
        }
    }

    private void addLowercaseWords(List<String[]> words, String suffix) throws InterruptedException {
        for (String[] word : words) {
            StringBuilder buf = new StringBuilder();
            for (String w : word) {
                buf.append(w);
            }
            buf.append(suffix);
            if (spec.conforms(buf.toString())) {
                queue.put(buf.toString().getBytes());
            }
        }
    }

    private void addMixedcaseWords(List<String[]> words, String suffix) throws InterruptedException {
        for (String[] word : words) {
            StringBuilder buf = new StringBuilder();
            for (String w : word) {
                buf.append(mixedCase(w));
            }
            buf.append(suffix);
            if (spec.conforms(buf.toString())) {
                queue.put(buf.toString().getBytes());
            }
        }
    }

    private String mixedCase(String lowercase) {
        StringBuilder mixed = new StringBuilder(lowercase);
        mixed.setCharAt(0, Character.toUpperCase(mixed.charAt(0)));
        return mixed.toString();
    }

    private void addMostCommonSuffixes(List<String[]> words) throws InterruptedException {
        if (spec.isLowercaseOK()) {
            for (String suffix : COMMON_SUFFIXES) {
                addLowercaseWords(words, suffix);
            }
        }

        for (String suffix : COMMON_SUFFIXES) {
            addMixedcaseWords(words, suffix);
        }
    }

    private void addDateSuffixes(List<String[]> words) throws InterruptedException {
        int fromYear = 1970;
        int currentYear = Calendar.getInstance().get(Calendar.YEAR);

        List<String> dateSuffixes = new ArrayList<String>(101 + (currentYear - fromYear));
        for (int i = 0; i < 100; i++) {
            dateSuffixes.add(i < 10 ? "0" + i : "" + i);
        }

        for (int i = fromYear; i < currentYear + 1; i++) {
            dateSuffixes.add("" + i);
        }

        if (spec.isLowercaseOK()) {
            for (String suffix : dateSuffixes) {
                addLowercaseWords(words, suffix);
            }
        }

        for (String suffix : dateSuffixes) {
            addMixedcaseWords(words, suffix);
        }

    }

    private void addSuffixes(String word, String[] suffixes) throws InterruptedException {
        for (String suffix : suffixes) {
            String newWord = word + suffix;
            if (spec.conforms(newWord)) {
                queue.put(newWord.getBytes());
            }
        }
    }

    private void addCommon1337Variants(List<String[]> words) throws InterruptedException {
        Map<Character, String> variants = new HashMap<Character, String>();
        variants.put('a', testSpecialChars("4@"));
        variants.put('b', testSpecialChars("8"));
        variants.put('e', testSpecialChars("3"));
        variants.put('g', testSpecialChars("9"));
        variants.put('i', testSpecialChars("!1"));
        variants.put('k', testSpecialChars("X"));
        variants.put('l', testSpecialChars("17"));
        variants.put('o', testSpecialChars("0"));
        variants.put('s', testSpecialChars("5$"));

        String[] suffixes = new String[COMMON_SUFFIXES.length + 1];
        suffixes[0] = "";
        System.arraycopy(COMMON_SUFFIXES, 0, suffixes, 1, COMMON_SUFFIXES.length);

        if (spec.isLowercaseOK()) {
            addSubstitions(words, variants, false, suffixes);
        }
        addSubstitions(words, variants, true, suffixes);
    }

    private void addLessCommon1337Variants(List<String[]> words) throws InterruptedException {
        Map<Character, String> variants = new HashMap<Character, String>();
        variants.put('b', testSpecialChars("6"));
        variants.put('c', testSpecialChars("(<{"));
        variants.put('g', testSpecialChars("6&"));
        variants.put('h', testSpecialChars("#"));
        variants.put('i', testSpecialChars("|"));
        variants.put('j', testSpecialChars("]"));
        variants.put('l', testSpecialChars("|"));
        variants.put('n', testSpecialChars("~"));
        variants.put('p', testSpecialChars("?9"));
        variants.put('q', testSpecialChars("9"));
        variants.put('r', testSpecialChars("2"));
        variants.put('s', testSpecialChars("z"));
        variants.put('t', testSpecialChars("7+1"));
        variants.put('u', testSpecialChars("M"));
        variants.put('x', testSpecialChars("%"));
        variants.put('y', testSpecialChars("j"));
        variants.put('z', testSpecialChars("23%"));

        String[] suffixes = new String[COMMON_SUFFIXES.length + 1];
        suffixes[0] = "";
        System.arraycopy(COMMON_SUFFIXES, 0, suffixes, 1, COMMON_SUFFIXES.length);

        if (spec.isLowercaseOK()) {
            addSubstitions(words, variants, false, suffixes);
        }
        addSubstitions(words, variants, true, suffixes);
    }

    private void doubleUp1337Variants(List<String[]> words) throws InterruptedException {
        Map<Character, String> variants = new HashMap<Character, String>();
        variants.put('a', testSpecialChars("4@"));
        variants.put('b', testSpecialChars("86"));
        variants.put('c', testSpecialChars("(<{"));
        variants.put('e', testSpecialChars("3"));
        variants.put('g', testSpecialChars("69&"));
        variants.put('h', testSpecialChars("#"));
        variants.put('i', testSpecialChars("!1|"));
        variants.put('j', testSpecialChars("]"));
        variants.put('k', testSpecialChars("X"));
        variants.put('l', testSpecialChars("17|"));
        variants.put('n', testSpecialChars("~"));
        variants.put('o', testSpecialChars("0"));
        variants.put('p', testSpecialChars("?9"));
        variants.put('q', testSpecialChars("9"));
        variants.put('r', testSpecialChars("2"));
        variants.put('s', testSpecialChars("5z$"));
        variants.put('t', testSpecialChars("7+1"));
        variants.put('u', testSpecialChars("M"));
        variants.put('x', testSpecialChars("%"));
        variants.put('y', testSpecialChars("j"));
        variants.put('z', testSpecialChars("23%"));

        if (spec.isLowercaseOK()) {
            addDoubleSubstitutions(words, variants, false);
        }

        addDoubleSubstitutions(words, variants, true);

    }

    private void addSubstitions(List<String[]> words, Map<Character, String> substitions, boolean usedMixedCase, String[] suffixes) throws InterruptedException {
        for (String[] word : words) {
            StringBuilder buf = new StringBuilder();
            for (String w : word) {
                buf.append(usedMixedCase ? mixedCase(w) : w);
            }

            addSubstitions(buf.toString(), substitions, suffixes);
        }
    }

    private void addSubstitions(String base, Map<Character, String> substitutions, String[] suffixes) throws InterruptedException {
        for (int i = 0; i < base.length(); i++) {
            char c = base.charAt(i);
            String subs = substitutions.get(c);
            if (subs != null) {
                StringBuilder buf = new StringBuilder(base);
                for (int j = 0; j < subs.length(); j++) {
                    buf.setCharAt(i, subs.charAt(j));
                    String newWord = buf.toString();
                    addSuffixes(newWord, suffixes);
                }
            }
        }
    }

    private void addDoubleSubstitutions(List<String[]> words, Map<Character, String> substitions, boolean usedMixedCase) throws InterruptedException {
        for (String[] word : words) {
            StringBuilder buf = new StringBuilder();
            for (String w : word) {
                buf.append(usedMixedCase ? mixedCase(w) : w);
            }

            addDoubleSubstitutions(buf.toString(), substitions);
        }
    }

    private void addDoubleSubstitutions(String base, Map<Character, String> substitions) throws InterruptedException {
        for (int i = 0; i < base.length() - 1; i++) {
            char c1 = base.charAt(i);
            String subs1 = substitions.get(c1);
            if (subs1 != null) {
                StringBuilder bufFirstSub = new StringBuilder(base);
                for (int subIndex1 = 0; subIndex1 < subs1.length(); subIndex1++) {
                    bufFirstSub.setCharAt(i, subs1.charAt(subIndex1));

                    for (int j = i + 1; j < base.length(); j++) {
                        char c2 = base.charAt(j);
                        String subs2 = substitions.get(c2);
                        if (subs2 != null) {
                            StringBuilder bufSecondSub = new StringBuilder(bufFirstSub.toString());
                            for (int subIndex2 = 0; subIndex2 < subs2.length(); subIndex2++) {
                                bufSecondSub.setCharAt(j, subs2.charAt(subIndex2));
                                String newWord = bufSecondSub.toString();
                                if (spec.conforms(newWord)) {
                                    queue.put(newWord.getBytes());
                                }
                            }
                        }
                    }
                }
            }
        }

    }

    private String testSpecialChars(String chars) {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < chars.length(); i++) {
            char c = chars.charAt(i);
            if (Character.isLetterOrDigit(c) || spec.isSpecialCharOK(c)) {
                buf.append(c);
            }
        }
        return buf.toString();
    }

    private void addPhrases(List<String[]> words) throws InterruptedException {
        if (spec.isSpacesOK()) {
            String[] phraseSuffixes = {"", ".", "!", "?"};
            for (String[] word : words) {
                StringBuilder phraseBuf = new StringBuilder();
                for (String w : word) {
                    phraseBuf.append(w);
                    phraseBuf.append(" ");
                }
                String phrase = phraseBuf.toString().trim();
                addSuffixes(phrase, phraseSuffixes);
                addSuffixes(mixedCase(phrase), phraseSuffixes);
            }
        }
    }

    //TODO: if spec allows, make combos with more than just two words
    private List<String[]> makeWordCombos() {
        ArrayList<String[]> comboList = new ArrayList<String[]>(words.size() * words.size());
        for (String[] firstWord : words) {
            for (String[] secondWord : words) {
                String[] combo = new String[2];
                combo[0] = firstWord[0];
                combo[1] = secondWord[0];
                comboList.add(combo);
            }
        }
        return comboList;
    }


    public static void main(String[] args) {
        ArrayList<String> inputList = new ArrayList<String>();
        inputList.add("Professionally");
        inputList.add("Evil");

        PasswordSpec spec = new PasswordSpec(6, 20, 1, 0, 0, 1, 0, true, "$#%", true);

        MasherGenerator generator = new MasherGenerator("testmashergen", inputList, spec);

        while (generator.hasMorePayloads()) {
            System.out.println(new String(generator.getNextPayload(null)));

        }
    }
}
