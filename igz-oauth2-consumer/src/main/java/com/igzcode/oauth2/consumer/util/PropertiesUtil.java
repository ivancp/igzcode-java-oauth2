package com.igzcode.oauth2.consumer.util;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Properties;

import com.igzcode.oauth2.consumer.IgzOAuthClient;


public class PropertiesUtil {

	private static Properties properties;

	public PropertiesUtil() {
		// TODO Auto-generated constructor stub
	}

	public static String getString( String p_key ){
		getProperties();
		return properties.getProperty( p_key );
	}

	private static void getProperties(){
		if( properties == null ){
			try {
				File propertiesFile = new File(IgzOAuthClient.class.getClassLoader().getResource("oauth2.properties").toURI());

				properties = new Properties();
				properties.load( new FileInputStream(propertiesFile) );

			} catch (URISyntaxException e) {
				e.printStackTrace();
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}
