package com.professionallyevil.co2.laudanum;

import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;

public class JSPShellPayloadType extends PayloadType {
    @Override
    public void savePayload(Component parentComponent, String acceptIPs, String acceptToken) throws Exception {
        File file = chooseFile(parentComponent, "shell.jsp", "Choose jsp filename");
        if(file != null){
            FileOutputStream fos = new FileOutputStream(file);
            processTemplate(fos, renderList(acceptIPs.split(","), ",", "\""),acceptToken);

        }
    }

    @Override
    String getTemplate() {
        return "com/professionallyevil/co2/laudanum/java/shell.jsp";
    }
}
