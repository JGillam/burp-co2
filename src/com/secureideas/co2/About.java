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

package com.secureideas.co2;

import java.awt.*;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;


/**
 * This class handles the About tab logic.
 */
public class About implements Co2Configurable{

    AboutTab tab = new AboutTab();
    String build;

    public About(){
        build = loadBuild();
        tab.setText("<html><body><h1>About Co2</h1>" +
                "Version: " + Co2Extender.VERSION +
                " (Build: " + build + ")" +
                "<h2>Description</h2>" +
                "Co2 is a Burp Extension that includes multiple enhancements to Portswigger's Burp Suite Tool" +
     //           "Additional information can be obtained at <a href=\\\"http://co2.professionallyevil.com>co2.professionallyevil.com</a>"+
                "<h2>License</h2>" +
                "Copyright (c) 2014 Jason Gillam<br/>" +
                "<br/>" +
                "  Licensed under the Apache License, Version 2.0 (the \"License\");<br/>" +
                "  you may not use this file except in compliance with the License.<br/>" +
                "  You may obtain a copy of the License at<br/>" +
                " <br/>" +
                " &nbsp;&nbsp;&nbsp;&nbsp;http://www.apache.org/licenses/LICENSE-2.0<br/>" +
                " <br/>" +
                " Unless required by applicable law or agreed to in writing, software<br/>" +
                " distributed under the License is distributed on an \"AS IS\" BASIS,<br/>" +
                " WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.<br/>" +
                " See the License for the specific language governing permissions and<br/>" +
                " limitations under the License.<br/>"+

                "<h2>Bugs and Feature Requests</h2>" +
                "Bug tracking for Co2 is at <a href=\"https://code.google.com/p/burp-co2/issues/list\">code.google.com/p/burp-co2/</a>" +


                "</body></html>");
    }

    @Override
    public Component getTabComponent() {
        return tab.getMainPanel();
    }

    @Override
    public String getTabTitle() {
        return "About";
    }

    // NOTE: this always seems to come back one number behind - seems to be an issue with IntelliJ's build pre-processing order.
    private String loadBuild(){
        try {
            InputStream inStream = About.this.getClass().getClassLoader().getResourceAsStream("com/secureideas/co2/build.txt");
            Properties buildProps = new Properties();
            buildProps.load(inStream);
            inStream.close();
            return buildProps.getProperty("build.number");
        } catch (IOException e) {
            return "?";
        }


    }
}
