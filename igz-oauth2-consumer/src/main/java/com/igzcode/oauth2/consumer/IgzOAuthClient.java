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

import javax.servlet.http.HttpServletRequest;
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

	private String grantType;
	private String applicationId;
	private String applicationSecret;
	private String redirectUrl;
	private String tokenLocation;
	private String authLocation;
	
	private String authServletPath;
	private String loginEndPoint;

	private int accessTokenTries = 0;

	public IgzOAuthClient (String p_filePath) {
	    PropertiesUtil propertiesUtil = new PropertiesUtil(p_filePath);
	    
	    applicationId = propertiesUtil.getString( APP_ID );
	    grantType = propertiesUtil.getString( GRANT_TYPE );
	    authLocation = propertiesUtil.getString( AUTH_LOCATION );
	    tokenLocation = propertiesUtil.getString( TOKEN_LOCATION );
	    applicationSecret = propertiesUtil.getString( APP_SECRET );
	    redirectUrl = propertiesUtil.getString( REDIRECT_URI );
	    authServletPath = propertiesUtil.getString( AUTH_SERVLET_PATH );
	    loginEndPoint =  propertiesUtil.getString( LOGIN_ENDPOINT );
	}

	public Date getExpiresIn(HttpServletRequest p_request) {
	    return (Date) p_request.getSession().getAttribute(OAuth.OAUTH_EXPIRES_IN);
	}
	
	public String getAccessToken(HttpServletRequest p_request) {
	    return (String) p_request.getSession().getAttribute(OAuth.OAUTH_BEARER_TOKEN);
	    
	}
	
	public String getApplicationId(){
		return applicationId;
	}

	public String getLoginEndPoint(){
		return loginEndPoint;
	}

	public String getGrantType(){
		return grantType;
	}

	public String getAuthServletPath(){
		return authServletPath;
	}

	public String getAuthLocation(){
		return authLocation;
	}

	public String getTokenLocation(){
		return tokenLocation;
	}

	public String getApplicationSecret(){
		return applicationSecret;
	}

	public String getRedirectUrl(){
		return redirectUrl;
	}

	public HttpURLConnection doGet ( String p_url, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.GET, null, null );
	}

	public HttpURLConnection doGet ( String p_url, int timeout, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.GET, null, timeout );
	}

	public HttpURLConnection doPost ( String p_url, Map<String, String> p_params, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.POST, p_params, null );
	}
	public HttpURLConnection doPost ( String p_url, Map<String, String> p_params, int timeout, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.POST, p_params, timeout );
	}

	// TODO
//	public HttpURLConnection doPost ( String p_url, String rawParams, int timeout, String type, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
//	    return doCall( req, p_url, OAuth.HttpMethod.POST, null, rawParams, timeout );
//	}

	public HttpURLConnection doPut ( String p_url, Map<String, String> p_params, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.PUT, p_params, null );
	}

	public HttpURLConnection doPut ( String p_url, Map<String, String> p_params, int timeout, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.PUT, p_params, timeout );
	}

	public HttpURLConnection doDelete ( String p_url, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.DELETE, null, null );
	}
	public HttpURLConnection doDelete ( String p_url, int timeout, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.DELETE, null, timeout );
	}

	private HttpURLConnection doCall ( HttpServletRequest req, String url, String method, Map<String, String> params, Integer timeout ) throws IOException, OAuthSystemException, OAuthProblemException {

	    Date expiresIn = getExpiresIn(req);
	    String accessToken = getAccessToken(req);
	    
		// Check if access token is null or has been expired
		if ( accessToken == null || ( expiresIn != null && new Date().getTime() >= expiresIn.getTime() ) ) {
		    logger.info("ACCESS TOKEN NULL OR EXPIRED accesToken[" + accessToken + "]");
		    
			accessToken = null;
			
			if( GrantType.CLIENT_CREDENTIALS.toString().equals( getGrantType() )) {
				getNewAccesToken(req);
				
				return doCall( req, url, method, params, timeout );
			} else if(  GrantType.AUTHORIZATION_CODE.toString().equals( getGrantType() ) ) {
				 throw OAuthProblemException.error(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT).description( OAuthError.TokenResponse.UNAUTHORIZED_CLIENT );
			} else {
				getNewAccesToken(req);
				
				return doCall( req, url, method, params, timeout );
			}

		} else {
			logger.info("TRY CALL accesToken[" + accessToken + "] url[" + url + "] method[" + method + "]");

			HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();

			conn.setRequestProperty(OAuth.HeaderType.AUTHORIZATION, OAuth.OAUTH_HEADER_NAME + " " + accessToken );
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

				accessToken = null;
				getNewAccesToken(req);
				return doCall( req, url, method, params, timeout );

			} else {
				logger.info("RESPONSE OK ");

				accessTokenTries = 0;
				return conn;
			}
		}
	}

	private synchronized void getNewAccesToken(HttpServletRequest req) throws OAuthSystemException, OAuthProblemException {
	    
	    String accessToken = getAccessToken(req);
	    
	    // Due to synchronized method, we must check if an call has assigned access token value before
	    if ( accessToken != null ) {
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

			accessToken = oAuthResponse.getAccessToken();

			Date expiresIn = new Date();
			expiresIn.setTime( expiresIn.getTime() + (oAuthResponse.getExpiresIn() * 1000) );
			
			req.getSession().setAttribute(OAuth.OAUTH_BEARER_TOKEN, accessToken);
			req.getSession().setAttribute(OAuth.OAUTH_EXPIRES_IN, expiresIn);

			logger.info("NEW TOKEN[" + accessToken + "] EXPIRES IN[" + expiresIn + "]");
			
		}
	}


	private byte[] getPayload (Map<String, String> params) throws UnsupportedEncodingException {
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
