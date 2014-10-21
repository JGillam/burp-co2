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

package burp;

import com.professionallyevil.co2.Co2Extender;
import com.professionallyevil.co2.laudanum.LaudanumCo2Extender;

public class BurpExtender implements IBurpExtender {
    private final Co2Extender co2Extender = new LaudanumCo2Extender();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        co2Extender.registerExtenderCallbacks(callbacks);
    }
}
