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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PasswordSpec {

    private int minChars, maxChars, minAlpha, minUpper, minLower, minNumeric, minSpecial;
    private boolean spacesOK;
    private static Pattern alphaPattern = Pattern.compile("[a-zA-Z]");
    private static Pattern uppercasePattern = Pattern.compile("[A-Z]");
    private static Pattern lowercasePattern = Pattern.compile("[a-z]");
    private static Pattern numericPattern = Pattern.compile("[0-9]");
    private Pattern specialPattern;
    // TODO: handle situation where entire password is uppercase

    public PasswordSpec(int minChars, int maxChars, int minAlpha, int minUpper, int minLower, int minNumeric, int minSpecial,
                        boolean restrictSpecial, String special, boolean spacesOK) {
        this.minChars = minChars;
        this.maxChars = maxChars;
        this.minAlpha = minAlpha;
        this.minUpper = minUpper;
        this.minLower = minLower;
        this.minNumeric = minNumeric;
        this.minSpecial = minSpecial;
        this.spacesOK = spacesOK;
        this.specialPattern = restrictSpecial?Pattern.compile("["+Pattern.quote(special)+"]"):Pattern.compile("\\p{Punct}");
    }

    public boolean conforms(String word) {
        if(word.length() < this.minChars || word.length() > maxChars) {
            return false;
        }

        if(minAlpha > 0) {
            Matcher m = alphaPattern.matcher(word);
            for(int r=0;r<minAlpha;r++){
                if(!m.find()){
                    return false;
                }
            }
        }

        if (minUpper > 0) {
            Matcher m = uppercasePattern.matcher(word);
            for(int r=0;r<minUpper;r++){
                if(!m.find()){
                    return false;
                }
            }
        }

       if (minLower > 0) {
            Matcher m = lowercasePattern.matcher(word);
            for(int r=0;r<minLower;r++){
                if(!m.find()){
                    return false;
                }
            }
       }

        if (minNumeric > 0) {
            Matcher m = numericPattern.matcher(word);
            for(int r=0;r<minNumeric;r++){
                if(!m.find()){
                    return false;
                }
            }
        }

        if (minSpecial > 0) {
            Matcher m = specialPattern.matcher(word);
            for(int r=0;r<minSpecial;r++){
                if(!m.find()){
                    return false;
                }
            }
        }

        return !(!spacesOK && word.contains(" "));

    }

    public boolean isSpacesOK(){
        return spacesOK;
    }

    public boolean isLowercaseOK(){
        return minUpper == 0;
    }

    public boolean isSpecialCharOK(Character symbol) {
        Matcher m = specialPattern.matcher(""+symbol);
        return m.find();
    }

//    Some light-weight unit testing to make sure this works
//    public static void main(String[] args) {
//        PasswordSpec spec = new PasswordSpec(0, 10, 1, 1, 2, 1, true, "@#$%^&*.", false);
//
//        System.out.println("password: "+spec.conforms("password"));
//        System.out.println("passwordpassword: "+spec.conforms("passwordpassword"));
//        System.out.println("pass word: "+spec.conforms("pass word"));
//        System.out.println("Password: "+spec.conforms("Password"));
//        System.out.println("Passw0rd: "+spec.conforms("Passw0rd"));
//        System.out.println("passw0rd: "+spec.conforms("passw0rd"));
//        System.out.println("PASSWORD: "+spec.conforms("PASSWORD"));
//        System.out.println("Pa55word: "+spec.conforms("Pa55word"));
//        System.out.println("Pass w0rd: "+spec.conforms("Pass w0rd"));
//        System.out.println("Pa55word!: "+spec.conforms("Pa55word!"));
//        System.out.println("Pa55word.: "+spec.conforms("Pa55word."));
//
//    }
}
