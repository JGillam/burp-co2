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

import burp.IIntruderAttack;
import burp.IIntruderPayloadGenerator;
import burp.IIntruderPayloadGeneratorFactory;

import java.util.Collection;
import java.util.List;

public class MasherGeneratorFactory implements IIntruderPayloadGeneratorFactory{

    String name;
    Collection<String> input;
    PasswordSpec spec;

    public MasherGeneratorFactory(String name, Collection<String> input, PasswordSpec spec){
        this.name = name;
        this.input = input;
        this.spec = spec;
    }


    @Override
    public String getGeneratorName() {
        return name;
    }

    @Override
    public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {
        return null;
    }
}
