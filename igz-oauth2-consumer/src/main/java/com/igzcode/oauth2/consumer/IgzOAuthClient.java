package com.igzcode.oauth2.consumer;


import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Date;
import java.util.Map;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletResponse;

import org.apache.amber.oauth2.client.OAuthClient;
import org.apache.amber.oauth2.client.URLConnectionClient;
import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.amber.oauth2.common.OAuth;
import org.apache.amber.oauth2.common.error.OAuthError;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.message.types.GrantType;

import com.igzcode.oauth2.consumer.util.PropertiesUtil;


public class IgzOAuthClient {

	protected static final Logger logger = Logger.getLogger(IgzOAuthClient.class.getName());

	private static final String APP_ID = "oauth2.appId";
	private static final String APP_SECRET = "oauth2.appSecret";
	private static final String TOKEN_LOCATION = "oauth2.tokenEndPoint";
	private static final String AUTH_LOCATION = "oauth2.authEndPoint";
	private static final String REDIRECT_URI = "oauth2.redirecUrl";
	private static final String GRANT_TYPE = "oauth2.grantType";
	private static final String AUTH_SERVLET_PATH = "oauth2.authServletPath";
	private static final String LOGIN_ENDPOINT = "oauth2.loginServletPath";
	

	private static final String ENCODING = "UTF-8";

	private static String accesToken = null;
	private static Date expiresIn = null;

	private static String grantType;
	private static String applicationId;
	private static String applicationSecret;
	private static String redirectUrl;
	private static String tokenLocation;
	private static String authLocation;
	
	private static String authServletPath;
	private static String loginEndPoint;

	private static int accessTokenTries = 0;

	private IgzOAuthClient() {}
	
	static {
	    applicationId = PropertiesUtil.getString( APP_ID );
	    grantType = PropertiesUtil.getString( GRANT_TYPE );
	    authLocation = PropertiesUtil.getString( AUTH_LOCATION );
	    tokenLocation = PropertiesUtil.getString( TOKEN_LOCATION );
	    applicationSecret = PropertiesUtil.getString( APP_SECRET );
	    redirectUrl = PropertiesUtil.getString( REDIRECT_URI );
	    authServletPath = PropertiesUtil.getString( AUTH_SERVLET_PATH );
	    loginEndPoint =  PropertiesUtil.getString( LOGIN_ENDPOINT );
	}

	public static void setAccessToken( String p_accessToken ){
		accesToken = p_accessToken;
	}
	
	public static String getApplicationId(){
		return applicationId;
	}

	public static String getLoginEndPoint(){
		return loginEndPoint;
	}

	public static String getGrantType(){
		return grantType;
	}

	public static String getAuthServletPath(){
		return authServletPath;
	}

	public static String getAuthLocation(){
		return authLocation;
	}

	public static String getTokenLocation(){
		return tokenLocation;
	}

	public static String getApplicationSecret(){
		return applicationSecret;
	}

	public static String getRedirectUrl(){
		return redirectUrl;
	}

	public static HttpURLConnection doGet ( String p_url ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_url, OAuth.HttpMethod.GET, null, null );
	}

	public static HttpURLConnection doGet ( String p_url, int timeout ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_url, OAuth.HttpMethod.GET, null, timeout );
	}

	public static HttpURLConnection doPost ( String p_url, Map<String, String> p_params ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_url, OAuth.HttpMethod.POST, p_params, null );
	}
	public static HttpURLConnection doPost ( String p_url, Map<String, String> p_params, int timeout ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_url, OAuth.HttpMethod.POST, p_params, timeout );
	}

	public static HttpURLConnection doPut ( String p_url, Map<String, String> p_params ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_url, OAuth.HttpMethod.PUT, p_params, null );
	}

	public static HttpURLConnection doPut ( String p_url, Map<String, String> p_params, int timeout ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_url, OAuth.HttpMethod.PUT, p_params, timeout );
	}

	public static HttpURLConnection doDelete ( String p_url ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_url, OAuth.HttpMethod.DELETE, null, null );
	}
	public static HttpURLConnection doDelete ( String p_url, int timeout ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_url, OAuth.HttpMethod.DELETE, null, timeout );
	}

	private static HttpURLConnection doCall ( String url, String method, Map<String, String> params, Integer timeout ) throws IOException, OAuthSystemException, OAuthProblemException {

		// Check if access token is null or has been expired
		if ( accesToken == null || ( expiresIn != null && new Date().getTime() >= expiresIn.getTime() ) ) {
		    logger.info("ACCESS TOKEN NULL OR EXPIRED accesToken[" + accesToken + "]");
		    
			accesToken = null;
			
			if( GrantType.CLIENT_CREDENTIALS.toString().equals( getGrantType() )) {
				getNewAccesToken();
				
				return doCall( url, method, params, timeout );
			} else if(  GrantType.AUTHORIZATION_CODE.toString().equals( getGrantType() ) ) {
				 throw OAuthProblemException.error(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT).description( OAuthError.TokenResponse.UNAUTHORIZED_CLIENT );
			} else {
				getNewAccesToken();
				
				return doCall( url, method, params, timeout );
			}

		} else {
			logger.info("TRY CALL accesToken[" + accesToken + "] url[" + url + "] method[" + method + "]");

			HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();

			conn.setRequestProperty(OAuth.HeaderType.AUTHORIZATION, OAuth.OAUTH_HEADER_NAME + " " + accesToken );
			conn.setRequestMethod( method );
			conn.setRequestProperty(OAuth.HeaderType.CONTENT_TYPE, OAuth.ContentType.URL_ENCODED + ";charset="+ENCODING);
			conn.setRequestProperty("Accept-Charset", ENCODING);

			if ( timeout != null && timeout > 0 ) {
				logger.info("SET CONNECTION TIMEOUT: " + timeout);
				conn.setConnectTimeout(timeout);
			}

			conn.setDoInput(true);
			if ( method == OAuth.HttpMethod.POST || method == OAuth.HttpMethod.PUT ) {
			    conn.setDoOutput(true);
			}
			
			if ( params != null && params.size() > 0 ) {
				OutputStream output = conn.getOutputStream();
				output.write( getPayload(params) );
				output.flush();
				output.close();
			}
			
			logger.info("GET RESPONSE EXPIRATION[" + conn.getExpiration() +"] READ TIMEOUT[" + conn.getReadTimeout() + "]" );

			if ( conn.getResponseCode() == HttpServletResponse.SC_UNAUTHORIZED ) {
				logger.info("UNAUTHORIZED CLIENT");

				accesToken = null;
				getNewAccesToken();
				return doCall( url, method, params, timeout );

			} else {
				logger.info("RESPONSE OK ");

				accessTokenTries = 0;
				return conn;
			}
		}
	}

	private synchronized static void getNewAccesToken() throws OAuthSystemException, OAuthProblemException {
	    
	    // Due to synchronized method, we must check if an call has assigned access token value before
	    if ( accesToken != null ) {
	        return;
	    }
	    
	    accessTokenTries ++;
        if( accessTokenTries > 3 ) {
            logger.info("GET NEW ACCESS TOKEN: ATTEMPTS EXCEEDED");
            throw OAuthProblemException.error(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT).description( OAuthError.TokenResponse.INVALID_CLIENT );
        }

        logger.info("GET NEW ACCESS TOKEN: TokenLocation[" + getTokenLocation() + "] GrantType[" + getGrantType() + "] AppId[" + getApplicationId() + "] AppSecret[" + getApplicationSecret() + "] RedirectUrl[" + getRedirectUrl() + "]");
		
        if( GrantType.CLIENT_CREDENTIALS.toString().equals( getGrantType() )) {

			OAuthClientRequest request = OAuthClientRequest
					.tokenLocation( getTokenLocation() )
					.setGrantType( GrantType.CLIENT_CREDENTIALS )
					.setClientId( getApplicationId() )
					.setClientSecret( getApplicationSecret() )
					.setRedirectURI( getRedirectUrl() )
					.buildBodyMessage();

			OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
			OAuthAccessTokenResponse oAuthResponse = oAuthClient.accessToken(request);

			accesToken = oAuthResponse.getAccessToken();

			expiresIn = new Date();
			expiresIn.setTime( expiresIn.getTime() + (oAuthResponse.getExpiresIn() * 1000) );

			logger.info("NEW TOKEN[" + accesToken + "] EXPIRES IN[" + expiresIn + "]");
			
		}
	}


	private static byte[] getPayload (Map<String, String> params) throws UnsupportedEncodingException {
		StringBuilder sbPayload = new StringBuilder("");
		
		for ( String key : params.keySet() ) {
		    
		    String value = params.get(key);
            
            // if value is null, URLEncoder will raise a NullPointerException
            if ( value == null ) {
                continue;
            }

            sbPayload.append("&");
            sbPayload.append(key);
            sbPayload.append("=");
            sbPayload.append( URLEncoder.encode(value, ENCODING) );
		}
		
		// if all param values are null, sbPayload will be ""
		if ( sbPayload.length() > 0 ) {
		    sbPayload.deleteCharAt(0); // Delete initial &
		}

		return sbPayload.toString().getBytes(ENCODING);
	}

}
