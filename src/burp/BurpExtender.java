package burp;

import com.secureideas.co2.*;

/**
 * User: jasong
 * Date: 12/10/13
 * Time: 6:57 PM
 * BurpExtender implementation for Burp Co2
 */
public class BurpExtender implements IBurpExtender {
    private final Co2Extender co2Extender = new Co2Extender();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        co2Extender.registerExtenderCallbacks(callbacks);
    }
}
