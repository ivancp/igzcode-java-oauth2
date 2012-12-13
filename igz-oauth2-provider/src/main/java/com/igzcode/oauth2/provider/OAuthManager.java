package com.igzcode.oauth2.provider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Properties;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.amber.oauth2.common.OAuth;
import org.apache.amber.oauth2.common.error.OAuthError;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.message.OAuthResponse;
import org.apache.amber.oauth2.rs.response.OAuthRSResponse;

import com.igzcode.oauth2.provider.exception.IgzOAuthException;


public class OAuthManager {

	protected static final Logger logger = Logger.getLogger(OAuthManager.class.getName());

	static private OAuthManager current;

	static synchronized public OAuthManager current () {
		if ( current == null ) {
			try {
				current = new OAuthManager();
			} catch (IgzOAuthException e) {
				e.printStackTrace();
			}
		}
		return current;
	}

	private Long expiresIn;
	private Properties properties;

	private OAuthManager () throws IgzOAuthException {
		File propertiesFile;
		try {
			propertiesFile = new File(OAuthManager.class.getClassLoader().getResource("oauth2.properties").toURI());

			this.properties = new Properties();
			this.properties.load( new FileInputStream(propertiesFile) );
			this.expiresIn = new Long(  this.properties.getProperty("oauth2.token.expires") );

		} catch (URISyntaxException e) {
			throw new IgzOAuthException("oauth2.properties file not found.");
		} catch (FileNotFoundException e) {
			throw new IgzOAuthException("oauth2.properties file not found.");
		} catch (IOException e) {
			throw new IgzOAuthException("oauth2.properties file not accesible.");
		}
	}

	public Long getExpires(){
		return this.expiresIn;
	}

	public String getProperty( String p_key ){
		return this.properties.getProperty( p_key );
	}

	public void respondWithError(HttpServletResponse resp, OAuthProblemException error)	throws IOException, ServletException {

		logger.info("OAuthManager respondWithError ERROR["+error.getError()+"] DESC["+error.getDescription()+"]");

		OAuthResponse oauthResponse = null;

		try {
			if (error.getError() == null || error.getError().equals("")) {
				oauthResponse = OAuthRSResponse.errorResponse(HttpServletResponse.SC_UNAUTHORIZED).buildHeaderMessage();
			} else {

				int responseCode = 401;
				if (error.getError().equals(OAuthError.CodeResponse.INVALID_REQUEST)) {
					responseCode = 400;
				}

				oauthResponse = OAuthRSResponse
						.errorResponse(responseCode)
						.setError(error.getError())
						.setErrorDescription(error.getDescription())
						.setErrorUri(error.getUri())
						.buildHeaderMessage();
			}

			logger.info("OAuth.HeaderType.WWW_AUTHENTICATE " + oauthResponse.getHeader(OAuth.HeaderType.WWW_AUTHENTICATE)+" STATUS["+oauthResponse.getResponseStatus()+"]");

			resp.addHeader(OAuth.HeaderType.WWW_AUTHENTICATE,oauthResponse.getHeader(OAuth.HeaderType.WWW_AUTHENTICATE));
			resp.sendError(oauthResponse.getResponseStatus());
		} catch (OAuthSystemException e) {
			e.printStackTrace();
			throw new ServletException(e);
		}
	}
}
