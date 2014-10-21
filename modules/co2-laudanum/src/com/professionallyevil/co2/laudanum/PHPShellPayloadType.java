package com.professionallyevil.co2.laudanum;

import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class PHPShellPayloadType extends PayloadType {

    @Override
    public void savePayload(Component parentComponent, String acceptIPs, String acceptToken) throws IOException {
        File file = chooseFile(parentComponent, "shell.php", "Choose php filename");
        if(file != null){
            FileOutputStream fos = new FileOutputStream(file);
            processTemplate(fos, renderList(acceptIPs.split(","), ",", "\""),acceptToken);

        }
    }

    @Override
    public String getTemplate(){
        return "com/professionallyevil/co2/laudanum/php/shell.php";
    }

}
