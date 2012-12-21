package com.igzcode.oauth2.consumer.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Properties;

import com.igzcode.oauth2.consumer.IgzOAuthClient;

public class PropertiesUtil {

    private Properties properties;

    public PropertiesUtil(String p_filePath) {
        if (properties == null) {
            try {
                File propertiesFile = new File(PropertiesUtil.class.getClassLoader().getResource(p_filePath).toURI());

                properties = new Properties();
                properties.load(new FileInputStream(propertiesFile));

            } catch (URISyntaxException e) {
                e.printStackTrace();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public String getString(String p_key) {
        return properties.getProperty(p_key);
    }
}
