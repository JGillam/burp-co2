package com.professionallyevil.co2.laudanum;

import burp.*;
import com.professionallyevil.co2.Co2Configurable;
import com.professionallyevil.co2.Co2Extender;
import com.professionallyevil.co2.Co2HelpLink;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

public class LaudanumClient implements Co2Configurable, ClipboardOwner, IContextMenuFactory {
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
    private JComboBox cmboPrepend;
    private JLabel helpButton;
    private JCheckBox chkUseRequestTemplate;
    private JLabel lblRequestTemplate;
    private String cwd = ".";
    private int commandStart = 0;
    private IBurpExtenderCallbacks callbacks;
    private static final String SETTING_LAUD_TOKEN = "LAUD.TOKEN";
    private static final String SETTING_LAUD_IP = "LAUD.IP";
    private byte[] requestTemplate = null;
    private Co2Extender extender;
    final java.util.List<String> history = new ArrayList<String>();
    int historyPointer = 0;


    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public LaudanumClient(final Co2Extender extender) {
        this.extender = extender;
        final Map<String, PayloadType> payloadTypes = new HashMap<String, PayloadType>();
        payloadTypes.put("PHP Shell", new PHPShellPayloadType());
        payloadTypes.put("JSP Shell", new JSPShellPayloadType());
        payloadTypes.put("WAR Shell", new WARShellPayloadType());
        payloadTypes.put("ASP Shell", new ASPShellPayloadType());
        payloadTypes.put("ASPX Shell", new ASPXShellPayloadType());

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
                } else {
                    super.keyReleased(e);
                }
            }

            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_UP) {
                    // TODO: handle history - this gets detected but not interrupted
                } else {
                    super.keyPressed(e);
                }
            }


        });
        txtConsole.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (txtConsole.getSelectedText().length() > 0) {       // todo: this may generate a NullPointerException
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
                    txtConsole.setText("Connecting to " + cmboProtocol.getSelectedItem().toString() + "://" + txtHostname.getText() + ":" + txtPort.getText() + txtResource.getText() + ".....\nwhoami\n");
                    runCommand("whoami", true);
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
        helpButton.addMouseListener(new Co2HelpLink("https://github.com/JGillam/burp-co2/wiki/SQLMapper", helpButton));

        chkUseRequestTemplate.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                cmboProtocol.setEnabled(!chkUseRequestTemplate.isSelected());
                txtPort.setEnabled(!chkUseRequestTemplate.isSelected());
                txtResource.setEnabled(!chkUseRequestTemplate.isSelected());
                txtHostname.setEnabled(!chkUseRequestTemplate.isSelected());
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
                i = cwd.lastIndexOf('\\');
                if (i > 0) {
                    cwd = cwd.substring(0, i);
                    if (cwd.indexOf('\\') == -1) {
                        cwd = cwd + '\\';
                    }
                }
            }
        } else {

            URL url = new URL(cmboProtocol.getSelectedItem() + "://" + txtHostname.getText() + ":" + txtPort.getText() + txtResource.getText());

            LaudanumRequest lreq;
            if (requestTemplate != null && chkUseRequestTemplate.isSelected()) {
                lreq = new LaudanumRequest(callbacks, cmboMethod.getSelectedItem().toString(), requestTemplate);
            } else {
                lreq = new LaudanumRequest(callbacks, url, cmboMethod.getSelectedItem().toString());
            }
            lreq.setCommand(command.startsWith("cd ") ? command : getPrepend() + command);
            lreq.setToken(txtAllowedToken.getText());
            lreq.setWorkingDirectory(cwd);

            //TODO: fix error output on PHP error

            byte[] responseBytes = callbacks.makeHttpRequest(txtHostname.getText(), new Integer(txtPort.getText()), "https".equalsIgnoreCase(cmboProtocol.getSelectedItem().toString()), lreq.getRequestBytes());

            LaudanumResponse lresp = new LaudanumResponse(callbacks, responseBytes);

            if (lresp.getCwd().length() > 0) {
                cwd = lresp.getCwd();
            }
            txtConsole.append(lresp.getStdout());
            txtConsole.append(lresp.getStderr());

        }
        history.add(command);
        historyPointer = history.size() - 1;
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

    @Override
    public String getTabCaption() {
        return getTabTitle();
    }

    @Override
    public Component getUiComponent() {
        return getTabComponent();
    }

    private String getPrepend() {
        return "<none>".equals(cmboPrepend.getSelectedItem().toString()) ? "" : cmboPrepend.getSelectedItem().toString();
    }

    @Override
    public java.util.List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages != null && messages.length > 0) {
            callbacks.printOutput("Messages in array: " + messages.length);
            java.util.List<JMenuItem> list = new ArrayList<JMenuItem>();
            final IHttpService service = messages[0].getHttpService();
            final byte[] sentRequestBytes = messages[0].getRequest();
            JMenuItem menuItem = new JMenuItem("Send to Laudanum");
            menuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    try {
                        requestTemplate = sentRequestBytes;
                        IRequestInfo info = callbacks.getHelpers().analyzeRequest(service, requestTemplate);
                        txtHostname.setText(service.getHost());
                        cmboProtocol.setSelectedItem(service.getProtocol());
                        txtResource.setText(info.getUrl().getFile());
                        txtPort.setText("" + info.getUrl().getPort());
                        lblRequestTemplate.setText(info.getUrl().toString());
                        chkUseRequestTemplate.setEnabled(true);
                        chkUseRequestTemplate.setSelected(true);
                        callbacks.printOutput("Laudanum received request template for " + info.getUrl().toString());
                        extender.selectConfigurableTab(LaudanumClient.this, true);
                    } catch (Exception e1) {
                        callbacks.printError(e1.getMessage());
                    }
                }
            });
            list.add(menuItem);
            return list;
        }

        return null;
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        mainPanel = new JPanel();
        mainPanel.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(4, 1, new Insets(5, 5, 5, 5), -1, -1));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel1, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer1 = new com.intellij.uiDesigner.core.Spacer();
        panel1.add(spacer1, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        helpButton = new JLabel();
        helpButton.setEnabled(true);
        helpButton.setIcon(new ImageIcon(getClass().getResource("/com/professionallyevil/co2/images/help.png")));
        helpButton.setText("");
        panel1.add(helpButton, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(3, 4, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel2, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel2.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "File Inclusion Setup"));
        txtAllowedToken = new JTextField();
        panel2.add(txtAllowedToken, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label1 = new JLabel();
        label1.setText("Token:");
        panel2.add(label1, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtAllowedIP = new JTextField();
        panel2.add(txtAllowedIP, new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        final JLabel label2 = new JLabel();
        label2.setText("Restrict IP:");
        panel2.add(label2, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        btnGenerate = new JButton();
        btnGenerate.setText("Gen New Token");
        panel2.add(btnGenerate, new com.intellij.uiDesigner.core.GridConstraints(2, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label3 = new JLabel();
        label3.setText("Type:");
        panel2.add(label3, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        cmboFiletype = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel1 = new DefaultComboBoxModel();
        defaultComboBoxModel1.addElement("PHP Shell");
        defaultComboBoxModel1.addElement("JSP Shell");
        defaultComboBoxModel1.addElement("WAR Shell");
        defaultComboBoxModel1.addElement("ASP Shell");
        defaultComboBoxModel1.addElement("ASPX Shell");
        cmboFiletype.setModel(defaultComboBoxModel1);
        panel2.add(cmboFiletype, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer2 = new com.intellij.uiDesigner.core.Spacer();
        panel2.add(spacer2, new com.intellij.uiDesigner.core.GridConstraints(1, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        btnSave = new JButton();
        btnSave.setText("Generate File");
        panel2.add(btnSave, new com.intellij.uiDesigner.core.GridConstraints(0, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer3 = new com.intellij.uiDesigner.core.Spacer();
        mainPanel.add(spacer3, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(4, 1, new Insets(0, 0, 0, 0), -1, -1));
        mainPanel.add(panel3, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panel3.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(Color.black), "Console"));
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(3, 4, new Insets(0, 0, 0, 0), -1, -1));
        panel3.add(panel4, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        cmboMethod = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel2 = new DefaultComboBoxModel();
        defaultComboBoxModel2.addElement("GET");
        defaultComboBoxModel2.addElement("POST");
        cmboMethod.setModel(defaultComboBoxModel2);
        cmboMethod.setToolTipText("What type of Laudanum parameters do you want to use?");
        panel4.add(cmboMethod, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtHostname = new JTextField();
        txtHostname.setText("hostname");
        panel4.add(txtHostname, new com.intellij.uiDesigner.core.GridConstraints(0, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        txtPostBody = new JTextField();
        txtPostBody.setEnabled(false);
        txtPostBody.setVisible(false);
        panel4.add(txtPostBody, new com.intellij.uiDesigner.core.GridConstraints(2, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        cmboProtocol = new JComboBox();
        final DefaultComboBoxModel defaultComboBoxModel3 = new DefaultComboBoxModel();
        defaultComboBoxModel3.addElement("http");
        defaultComboBoxModel3.addElement("https");
        cmboProtocol.setModel(defaultComboBoxModel3);
        panel4.add(cmboProtocol, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label4 = new JLabel();
        label4.setText("POST Body:");
        label4.setVisible(false);
        panel4.add(label4, new com.intellij.uiDesigner.core.GridConstraints(2, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label5 = new JLabel();
        label5.setText("Resource:");
        panel4.add(label5, new com.intellij.uiDesigner.core.GridConstraints(1, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        txtResource = new JTextField();
        txtResource.setText("/shell.php");
        panel4.add(txtResource, new com.intellij.uiDesigner.core.GridConstraints(1, 3, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        txtPort = new JTextField();
        txtPort.setText("80");
        panel4.add(txtPort, new com.intellij.uiDesigner.core.GridConstraints(1, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(45, -1), null, 0, false));
        final JLabel label6 = new JLabel();
        label6.setText("Host:");
        panel4.add(label6, new com.intellij.uiDesigner.core.GridConstraints(0, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label7 = new JLabel();
        label7.setText("Port:");
        panel4.add(label7, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JLabel label8 = new JLabel();
        label8.setText("Prepend:");
        panel4.add(label8, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        cmboPrepend = new JComboBox();
        cmboPrepend.setEditable(true);
        final DefaultComboBoxModel defaultComboBoxModel4 = new DefaultComboBoxModel();
        defaultComboBoxModel4.addElement("<none>");
        defaultComboBoxModel4.addElement("%ComSpec% /c");
        cmboPrepend.setModel(defaultComboBoxModel4);
        cmboPrepend.setToolTipText("Typically only used for ASP.");
        panel4.add(cmboPrepend, new com.intellij.uiDesigner.core.GridConstraints(2, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        panel3.add(scrollPane1, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        txtConsole = new JTextArea();
        txtConsole.setFont(new Font("Monospaced", txtConsole.getFont().getStyle(), txtConsole.getFont().getSize()));
        txtConsole.setLineWrap(true);
        txtConsole.setRows(20);
        scrollPane1.setViewportView(txtConsole);
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 3, new Insets(0, 0, 0, 0), -1, -1));
        panel3.add(panel5, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        btnConnect = new JButton();
        btnConnect.setText("re/Connect");
        panel5.add(btnConnect, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer4 = new com.intellij.uiDesigner.core.Spacer();
        panel5.add(spacer4, new com.intellij.uiDesigner.core.GridConstraints(0, 2, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer5 = new com.intellij.uiDesigner.core.Spacer();
        panel5.add(spacer5, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, 1, null, null, null, 0, false));
        final JPanel panel6 = new JPanel();
        panel6.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel3.add(panel6, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        chkUseRequestTemplate = new JCheckBox();
        chkUseRequestTemplate.setEnabled(false);
        chkUseRequestTemplate.setText("Use Request Template:");
        chkUseRequestTemplate.setToolTipText("Only enabled after a request has been sent to Laudanum.");
        panel6.add(chkUseRequestTemplate, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        lblRequestTemplate = new JLabel();
        lblRequestTemplate.setText("[Hint: Send a request to Laudanum]");
        panel6.add(lblRequestTemplate, new com.intellij.uiDesigner.core.GridConstraints(0, 1, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return mainPanel;
    }
}
