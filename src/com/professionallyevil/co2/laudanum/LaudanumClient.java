package com.professionallyevil.co2.laudanum;

import burp.IBurpExtenderCallbacks;
import burp.IParameter;
import burp.IResponseInfo;
import com.professionallyevil.co2.Co2Configurable;
import com.professionallyevil.co2.Co2Extender;

import javax.swing.*;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.ClipboardOwner;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class LaudanumClient implements Co2Configurable, ClipboardOwner {
    private JPanel mainPanel;
    private JTextField txtAllowedToken;
    private JTextField txtAllowedIP;
    private JButton btnGenerate;
    private JComboBox cmboMethod;
    private JTextField txtHostname;
    private JTextField txtPostBody;
    private JTextArea txtConsole;
    private JComboBox cmboProtocol;
    private JTextField txtPort;
    private JTextField txtResource;
    private JComboBox cmboFiletype;
    private JButton btnSave;
    private JButton btnConnect;
    private String cwd = ".";
    private int commandStart = 0;
    private IBurpExtenderCallbacks callbacks;
    private static final String SETTING_LAUD_TOKEN = "LAUD.TOKEN";
    private static final String SETTING_LAUD_IP = "LAUD.IP";

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public LaudanumClient(final Co2Extender extender) {
        final Map<String,PayloadType> payloadTypes = new HashMap<String,PayloadType>();
        payloadTypes.put("PHP Shell", new PHPShellPayloadType());
        payloadTypes.put("JSP Shell", new JSPShellPayloadType());
        payloadTypes.put("WAR Shell", new WARShellPayloadType());

        this.callbacks = extender.getCallbacks();
        String token = callbacks.loadExtensionSetting(SETTING_LAUD_TOKEN);
        if (token != null && token.length() > 0) {
            txtAllowedToken.setText(token);
        }
        String ips = callbacks.loadExtensionSetting(SETTING_LAUD_IP);
        if (ips != null && ips.length() > 0) {
            txtAllowedIP.setText(ips);
        }

        //showPrompt();
        ((AbstractDocument) txtConsole.getDocument()).setDocumentFilter(new DocumentFilter() {
            @Override
            public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {
                if (checkCommandPosition(offset)) {
                    super.remove(fb, offset, length);
                }
            }

            @Override
            public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs) throws BadLocationException {
                //if(checkCommandPosition(offset)) {
                super.replace(fb, offset, length, text, attrs);
                //}
            }

            @Override
            public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr) throws BadLocationException {
                super.insertString(fb, offset, string, attr);
            }

            private boolean checkCommandPosition(int offset) {
                return offset >= commandStart;
            }
        });

        txtConsole.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                super.keyReleased(e);
                if (e.getKeyCode() == KeyEvent.VK_ENTER) {
                    int currentPosition = txtConsole.getCaretPosition();
                    try {
                        String command = txtConsole.getText(commandStart, (currentPosition - commandStart - 1));

                        runCommand(command, false);
                    } catch (BadLocationException e1) {
                        callbacks.printError(e1.toString());
                    } catch (MalformedURLException e1) {
                        callbacks.printError(e1.toString());
                    } catch (NumberFormatException e1) {
                        callbacks.printError(e1.toString());
                    }
                }
            }
        });
        txtConsole.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (txtConsole.getSelectedText().length() > 0) {
                    Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                    StringSelection contents = new StringSelection(txtConsole.getSelectedText());
                    clipboard.setContents(contents, LaudanumClient.this);
                }
                txtConsole.setCaretPosition(txtConsole.getText().length());
            }
        });
        btnGenerate.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Random r = new Random();
                byte[] bytes = new byte[20];
                r.nextBytes(bytes);
                txtAllowedToken.setText(bytesToHex(bytes));
            }
        });
        btnSave.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                PayloadType pt = payloadTypes.get(cmboFiletype.getSelectedItem().toString());
                try {
                    pt.savePayload(mainPanel, txtAllowedIP.getText(), txtAllowedToken.getText());
                } catch (Exception e1) {
                    callbacks.printError("Error saving payload: " + e1.getMessage());
                    JOptionPane.showMessageDialog(mainPanel, "Error saving payload. " + e1.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        cmboMethod.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                txtPostBody.setEnabled(cmboMethod.getSelectedItem().equals("POST"));
            }
        });
        btnConnect.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    txtConsole.setText("Connecting to " + cmboProtocol.getSelectedItem().toString() + "://" + txtHostname.getText() + ":" + txtPort.getText() + txtResource.getText() + ".....");
                    runCommand("pwd", true);
                } catch (MalformedURLException e1) {
                    txtConsole.setText("Malformed URL.  Check your hostname and port.");
                    e1.printStackTrace();
                }
            }
        });

        txtAllowedToken.addPropertyChangeListener(new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                callbacks.saveExtensionSetting(SETTING_LAUD_TOKEN, txtAllowedToken.getText());
            }
        });

        txtAllowedIP.addPropertyChangeListener(new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                callbacks.saveExtensionSetting(SETTING_LAUD_IP, txtAllowedIP.getText());
            }
        });

        cmboProtocol.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (cmboProtocol.getSelectedItem().equals("http") && txtPort.getText().equals("443")) {
                    txtPort.setText("80");
                } else if (cmboProtocol.getSelectedItem().equals("https") && txtPort.getText().equals("80")) {
                    txtPort.setText("443");
                }
            }
        });

    }


    private void runCommand(String command, boolean muteOutput) throws MalformedURLException {
        if (command.equals("clear")) {
            txtConsole.setText("");
            commandStart = 0;
        } else if (command.equals("cd ..")) {
            int i = cwd.lastIndexOf('/');
            if (i == 0) {
                cwd = "/";
            } else if (i > -1) {
                cwd = cwd.substring(0, i);
            } else {
                i = cwd.lastIndexOf('\\');   // TODO: may need to adjust this for windows platforms... needs testing
                if (i > -1) {
                    cwd = cwd.substring(0, i);
                }
            }
        } else {

            URL url = new URL(cmboProtocol.getSelectedItem() + "://" + txtHostname.getText() + ":" + txtPort.getText() + txtResource.getText());

            byte[] requestBytes = callbacks.getHelpers().buildHttpRequest(url);
            byte paramType = IParameter.PARAM_URL;
            if (cmboMethod.getSelectedItem().toString().equals("POST")) {
                paramType = IParameter.PARAM_BODY;
            }

            IParameter ptoken = callbacks.getHelpers().buildParameter("laudtoken", txtAllowedToken.getText(), paramType);
            IParameter pcmd = callbacks.getHelpers().buildParameter("laudcmd", callbacks.getHelpers().base64Encode(command), paramType);
            IParameter pcwd = callbacks.getHelpers().buildParameter("laudcwd", callbacks.getHelpers().base64Encode(cwd), paramType);

            requestBytes = callbacks.getHelpers().addParameter(requestBytes, ptoken);
            requestBytes = callbacks.getHelpers().addParameter(requestBytes, pcmd);
            requestBytes = callbacks.getHelpers().addParameter(requestBytes, pcwd);

            //TODO: figure out how to support additional POST params
            //TODO: fix error output on PHP error

            byte[] responseBytes = callbacks.makeHttpRequest(txtHostname.getText(), new Integer(txtPort.getText()), cmboProtocol.getSelectedItem().equals("https"), requestBytes);

            IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(responseBytes);
            byte[] body = Arrays.copyOfRange(responseBytes, responseInfo.getBodyOffset(), responseBytes.length);
            String[] outputParams = callbacks.getHelpers().bytesToString(body).split(",");
            if (outputParams.length == 3) {
                if (!muteOutput) {
                    String output = new String(callbacks.getHelpers().base64Decode(outputParams[0]));
                    txtConsole.append(output);
                }
                String err = new String(callbacks.getHelpers().base64Decode(outputParams[1]));

                if (err.trim().length() > 0) {
                    txtConsole.append("\nOS ERROR: " + err);
                }
                String newcwd = new String(callbacks.getHelpers().base64Decode(outputParams[2]));

                if (newcwd.length() > 0) {
                    cwd = newcwd;
                }
            } else {
                txtConsole.append("\nLaudanum ERROR: " + callbacks.getHelpers().bytesToString(body));
            }
        }
        txtConsole.append("\n");
        showPrompt();
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private void showPrompt() {
        if (cwd.equals(".")) {
            txtConsole.append("laudanum> ");
        } else {
            txtConsole.append("laudanum[" + cwd + "]> ");
        }
        txtConsole.setCaretPosition(txtConsole.getText().length());
        commandStart = txtConsole.getCaretPosition();
        if (!txtConsole.hasFocus()) {
            txtConsole.grabFocus();
        }
    }


    @Override
    public Component getTabComponent() {
        return mainPanel;
    }

    @Override
    public String getTabTitle() {
        return "Laudanum";
    }

    @Override
    public void lostOwnership(Clipboard clipboard, Transferable contents) {
        // do nothing
    }
}
