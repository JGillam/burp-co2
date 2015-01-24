/*
 * Copyright (c) 2015 Jason Gillam
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

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class CO2Config {

    private Properties props = new Properties();
    private static CO2Config instance = new CO2Config();

    private CO2Config() {
        InputStream inStream = null;
        try {
            inStream = CO2Config.this.getClass().getClassLoader().getResourceAsStream("com/professionallyevil/co2/config.txt");
            props.load(inStream);
            inStream.close();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (inStream != null) {
                try {
                    inStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public static boolean isLoadedFromBappStore() {
        return Boolean.parseBoolean(instance.props.getProperty("bappstore", "false"));
    }


}
