package burp;

import com.professionallyevil.co2.*;

public class BurpExtender implements IBurpExtender {
    private final Co2Extender co2Extender = new Co2Extender();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        co2Extender.registerExtenderCallbacks(callbacks);
    }
}
