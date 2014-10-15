package com.professionallyevil.co2.laudanum;

import javax.swing.*;
import java.awt.*;
import java.io.*;

public abstract class PayloadType {

    public abstract void savePayload(Component parentComponent, String acceptIPs, String acceptToken) throws Exception;


     String renderList(String[] acceptIps, String delimiter, String enclosingChar) {
        StringBuilder ipslist = new StringBuilder();
        for (String ip : acceptIps) {
            ipslist.append(enclosingChar);
            ipslist.append(ip);
            ipslist.append(enclosingChar);
            ipslist.append(delimiter);
        }
        ipslist.deleteCharAt(ipslist.length() - delimiter.length());
        return ipslist.toString();
    }

     void processTemplate(OutputStream output, String acceptIPs, String acceptToken) throws IOException {
        InputStream inStream = this.getClass().getClassLoader().getResourceAsStream(getTemplate());
        BufferedReader reader = new BufferedReader(new InputStreamReader(inStream));

        String line = reader.readLine();
        while (line != null) {
            line = line.replace("${LAUD.IPS}", acceptIPs);
            line = line.replace("${LAUD.TOKEN}", acceptToken);
            output.write(line.getBytes());
            output.write("\n".getBytes());
            line = reader.readLine();
        }

        output.flush();
        output.close();
        inStream.close();
    }

    abstract String getTemplate();

    File chooseFile(Component parentComponent, String defaultName, String title) {
        final JFileChooser fc = new JFileChooser();
        fc.setDialogTitle(title);
        fc.setSelectedFile(new File(defaultName));
        int returnVal = fc.showSaveDialog(parentComponent);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            return fc.getSelectedFile();
        } else{
            return null;
        }
    }
}
