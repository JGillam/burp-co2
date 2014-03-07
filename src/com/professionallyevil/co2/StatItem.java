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

package com.professionallyevil.co2;

/**
 * A stat item is basically a weighted string.  This is what how sorting is handled in UserGenerator.  Simply
 * add StatItems to any collection that can do comparisons (i.e. that recognizes the Comparable interface).
 *
 */
public class StatItem implements Comparable {
    private String name;
    private int value;

    public StatItem(String name, int value) {
        this.name = name;
        this.value = value;
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof StatItem && ((StatItem)obj).getName().equals(name);
    }

    @Override
    public String toString() {
        return name;
    }

    public String getName(){
        return name;
    }

    public int getValue() {
        return value;
    }

    public void addValue(int value){
        this.value = this.value + value;
    }

    @Override
    public int compareTo(Object o) {
        if (o instanceof StatItem) {
            return  ((StatItem) o).getValue() > getValue() ? 1 : -1;
        } else {
            return -1;
        }
    }
}
