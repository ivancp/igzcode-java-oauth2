package com.igzcode.oauth2.consumer;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.amber.oauth2.client.OAuthClient;
import org.apache.amber.oauth2.client.URLConnectionClient;
import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.amber.oauth2.common.OAuth;
import org.apache.amber.oauth2.common.error.OAuthError;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.message.types.GrantType;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.igzcode.oauth2.consumer.util.PropertiesUtil;


public class IgzOAuthClient {

	protected static final Logger logger = Logger.getLogger(IgzOAuthClient.class.getName());

	private static final String APP_ID = "oauth2.appId";
	private static final String APP_SECRET = "oauth2.appSecret";
	private static final String TOKEN_LOCATION = "oauth2.tokenEndPoint";
	private static final String AUTH_LOCATION = "oauth2.authEndPoint";
	private static final String REDIRECT_URI = "oauth2.redirecUrl";
	private static final String REVOKE_URI = "oauth2.revokeUrl";
	private static final String GRANT_TYPE = "oauth2.grantType";
	private static final String AUTH_SERVLET_PATH = "oauth2.authServletPath";
	private static final String LOGIN_ENDPOINT = "oauth2.loginServletPath";
	private static final String DEFAULT_EXPIRES_IN = "oauth2.defaultexpiresin";
	private static final String CONNECTION_TIMEOUT = "oauth2.connectionTimeout";
	
	private static final Charset CHARSET = Charset.forName("UTF-8");
	

	private static final String ENCODING = "UTF-8";
	private static final String HTTP_PATCH = "PATCH";

	private String grantType;
	private String applicationId;
	private String applicationSecret;
	private String redirectUrl;
	private String revokeUrl;
	private String tokenLocation;
	private String authLocation;
	private Long defaultExpiresIn;
	private Integer connectionTimeout;
	
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
	    revokeUrl = propertiesUtil.getString( REVOKE_URI );
	    authServletPath = propertiesUtil.getString( AUTH_SERVLET_PATH );
	    loginEndPoint =  propertiesUtil.getString( LOGIN_ENDPOINT );
	    
	    try {
	    	connectionTimeout = Integer.parseInt(propertiesUtil.getString(CONNECTION_TIMEOUT));
	    } catch ( NumberFormatException e ) {
	    	connectionTimeout = 60000;
	    }
	    try {	    	
	    	defaultExpiresIn = Long.parseLong( propertiesUtil.getString(DEFAULT_EXPIRES_IN) );	
	    } catch ( NumberFormatException e ) {
	    	//logger.severe("Default Expired In is not a number, revise oauth2.properties file");
	    	defaultExpiresIn = null;
	    }
	}		

	public Integer getConnectionTimeout() {
		return connectionTimeout;
	}

	public void setConnectionTimeout(Integer connectionTimeout) {
		this.connectionTimeout = connectionTimeout;
	}
	
	public Long getDefaultExpiresIn() {
		return defaultExpiresIn;
	}

	public void setDefaultExpiresIn(Long defaultExpiresIn) {
		this.defaultExpiresIn = defaultExpiresIn;
	}

	public Date getExpiresIn(HttpSession session) {
	    return (Date) session.getAttribute(OAuth.OAUTH_EXPIRES_IN);
	}
	
	public String getAccessToken(HttpSession session) {
	    return (String) session.getAttribute(OAuth.OAUTH_BEARER_TOKEN);
	    
	}
	
	public String getRefreshToken(HttpSession session) {
	    return (String) session.getAttribute(OAuth.OAUTH_REFRESH_TOKEN);
	    
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

	public HttpURLConnection doGet ( String p_url, HttpSession session ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( session, p_url, OAuth.HttpMethod.GET, null, null, null, null );
	}

	public HttpURLConnection doGet ( String p_url, int timeout, HttpSession session ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( session, p_url, OAuth.HttpMethod.GET, null, timeout, null, null );
	}

	public HttpURLConnection doPost ( String p_url, Map<String, String> p_params, HttpSession session ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( session, p_url, OAuth.HttpMethod.POST, p_params, null, null, null );
	}
	public HttpURLConnection doPost ( String p_url, Map<String, String> p_params, int timeout, HttpSession session ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( session, p_url, OAuth.HttpMethod.POST, p_params, timeout, null, null );
	}

	public HttpURLConnection doPost ( String p_url, String rawParams, int timeout, String type, HttpSession session ) throws IOException, OAuthSystemException, OAuthProblemException {
	    return doCall( session, p_url, OAuth.HttpMethod.POST, null, timeout, rawParams, type );
	}
	
	public HttpURLConnection doPost ( String p_url, String rawParams, String type, HttpSession session ) throws IOException, OAuthSystemException, OAuthProblemException {
	    return doCall( session, p_url, OAuth.HttpMethod.POST, null, null, rawParams, type );
	}

	public HttpURLConnection doPut ( String p_url, Map<String, String> p_params, HttpSession session ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( session, p_url, OAuth.HttpMethod.PUT, p_params, null, null, null );
	}

	public HttpURLConnection doPut ( String p_url, Map<String, String> p_params, int timeout, HttpSession session ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( session, p_url, OAuth.HttpMethod.PUT, p_params, timeout, null, null );
	}
	
	public HttpURLConnection doPatch ( String p_url, Map<String, String> p_params, HttpSession session ) throws IOException, OAuthSystemException, OAuthProblemException {
	    return doCall( session, p_url, HTTP_PATCH, p_params, null, null, null );
	}
	
	public HttpURLConnection doPatch ( String p_url, Map<String, String> p_params, int timeout, HttpSession session ) throws IOException, OAuthSystemException, OAuthProblemException {
	    return doCall( session, p_url, HTTP_PATCH, p_params, timeout, null, null );
	}
	
	public HttpURLConnection doPatch ( String p_url, String rawParams, int timeout, String type, HttpSession session ) throws IOException, OAuthSystemException, OAuthProblemException {
        return doCall( session, p_url, HTTP_PATCH, null, timeout, rawParams, type );
    }
	
	public HttpURLConnection doPatch ( String p_url, String rawParams, String type, HttpSession session ) throws IOException, OAuthSystemException, OAuthProblemException {
        return doCall( session, p_url, HTTP_PATCH, null, null, rawParams, type );
    }

	public HttpURLConnection doDelete ( String p_url, HttpSession session ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( session, p_url, OAuth.HttpMethod.DELETE, null, null, null, null );
	}
	public HttpURLConnection doDelete ( String p_url, int timeout, HttpSession session ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( session, p_url, OAuth.HttpMethod.DELETE, null, timeout, null, null );
	}
	
	public HttpURLConnection doGet ( String p_url, HttpServletRequest p_request ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_request.getSession() , p_url, OAuth.HttpMethod.GET, null, null, null, null );
	}
	
	public HttpURLConnection doGet ( String p_url, int timeout, HttpServletRequest p_request ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_request.getSession(), p_url, OAuth.HttpMethod.GET, null, timeout, null, null );
	}
	
	public HttpURLConnection doPost ( String p_url, Map<String, String> p_params, HttpServletRequest p_request ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_request.getSession(), p_url, OAuth.HttpMethod.POST, p_params, null, null, null );
	}
	public HttpURLConnection doPost ( String p_url, Map<String, String> p_params, int timeout, HttpServletRequest p_request ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_request.getSession(), p_url, OAuth.HttpMethod.POST, p_params, timeout, null, null );
	}
	
	public HttpURLConnection doPost ( String p_url, String rawParams, int timeout, String type, HttpServletRequest p_request ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_request.getSession(), p_url, OAuth.HttpMethod.POST, null, timeout, rawParams, type );
	}
	
	public HttpURLConnection doPost ( String p_url, String rawParams, String type, HttpServletRequest p_request ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_request.getSession(), p_url, OAuth.HttpMethod.POST, null, null, rawParams, type );
	}
	
	public HttpURLConnection doPut ( String p_url, Map<String, String> p_params, HttpServletRequest p_request ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_request.getSession(), p_url, OAuth.HttpMethod.PUT, p_params, null, null, null );
	}
	
	public HttpURLConnection doPut ( String p_url, Map<String, String> p_params, int timeout, HttpServletRequest p_request ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_request.getSession(), p_url, OAuth.HttpMethod.PUT, p_params, timeout, null, null );
	}
	
	public HttpURLConnection doPatch ( String p_url, Map<String, String> p_params, HttpServletRequest p_request ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_request.getSession(), p_url, HTTP_PATCH, p_params, null, null, null );
	}
	
	public HttpURLConnection doPatch ( String p_url, Map<String, String> p_params, int timeout, HttpServletRequest p_request ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_request.getSession(), p_url, HTTP_PATCH, p_params, timeout, null, null );
	}
	
	public HttpURLConnection doPatch ( String p_url, String rawParams, int timeout, String type, HttpServletRequest p_request ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_request.getSession(), p_url, HTTP_PATCH, null, timeout, rawParams, type );
	}
	
	public HttpURLConnection doPatch ( String p_url, String rawParams, String type, HttpServletRequest p_request ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_request.getSession(), p_url, HTTP_PATCH, null, null, rawParams, type );
	}
	
	public HttpURLConnection doDelete ( String p_url, HttpServletRequest p_request ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_request.getSession(), p_url, OAuth.HttpMethod.DELETE, null, null, null, null );
	}
	public HttpURLConnection doDelete ( String p_url, int timeout, HttpServletRequest p_request ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( p_request.getSession(), p_url, OAuth.HttpMethod.DELETE, null, timeout, null, null );
	}

	private HttpURLConnection doCall ( HttpSession session, String url, String method, Map<String, String> params, Integer timeout, String rawParams, String type ) throws IOException, OAuthSystemException, OAuthProblemException {

	    Date expiresIn = getExpiresIn(session);
	    String accessToken = getAccessToken(session);
	    
		// Check if access token is null or has been expired
		if ( accessToken == null || ( expiresIn != null && new Date().getTime() >= expiresIn.getTime() )) {
		    logger.info("ACCESS TOKEN NULL accesToken[" + accessToken + "]");
		    
			accessToken = null;
			
			if( GrantType.CLIENT_CREDENTIALS.toString().equals( getGrantType() )) {
				getNewAccesToken(session);
				
				return doCall( session, url, method, params, timeout, rawParams, type );
			} else if(  GrantType.AUTHORIZATION_CODE.toString().equals( getGrantType() ) ) {
				 throw OAuthProblemException.error(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT).description( OAuthError.TokenResponse.UNAUTHORIZED_CLIENT );
			} else {
				getNewAccesToken(session);
				
				return doCall( session, url, method, params, timeout, rawParams, type );
			}

		} else {
			logger.info("TRY CALL accesToken[" + accessToken + "] url[" + url + "] method[" + method + "]");

			HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();

			conn.setRequestProperty(OAuth.HeaderType.AUTHORIZATION, OAuth.OAUTH_HEADER_NAME + " " + accessToken );
			conn.setRequestMethod( method );
			conn.setRequestProperty(OAuth.HeaderType.CONTENT_TYPE, OAuth.ContentType.URL_ENCODED + ";charset="+ENCODING);
			conn.setRequestProperty("Accept-Charset", ENCODING);
			
			if ( type != null ) {
                conn.setRequestProperty("Content-Type", type);
            }

			if ( timeout != null && timeout > 0 ) {
				logger.info("SET CONNECTION TIMEOUT: " + timeout);
				conn.setConnectTimeout(timeout);
			}

			conn.setDoInput(true);
			if ( method == OAuth.HttpMethod.POST || method == OAuth.HttpMethod.PUT || method == HTTP_PATCH ) {
			    conn.setDoOutput(true);
			}
			
			if ( (params != null && params.size() > 0) || rawParams != null ) {
				OutputStream output = conn.getOutputStream();
				output.write( (rawParams != null) ? rawParams.getBytes(CHARSET) : getPayload(params) );
				output.flush();
				output.close();
			}
			
			logger.info("GET RESPONSE EXPIRATION[" + conn.getExpiration() +"] READ TIMEOUT[" + conn.getReadTimeout() + "]" );

			if ( conn.getResponseCode() == HttpServletResponse.SC_UNAUTHORIZED ) {
				logger.info("UNAUTHORIZED CLIENT");

				session.setAttribute(OAuth.OAUTH_BEARER_TOKEN, null);
	            session.setAttribute(OAuth.OAUTH_EXPIRES_IN, null);
				session.setAttribute(OAuth.OAUTH_REFRESH_TOKEN, null);
	            
	            if ( GrantType.CLIENT_CREDENTIALS.toString().equals( getGrantType() ) ) {
                    getNewAccesToken(session);
                } else if(  GrantType.AUTHORIZATION_CODE.toString().equals( getGrantType() ) ) {
                    throw OAuthProblemException.error(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT).description( OAuthError.TokenResponse.UNAUTHORIZED_CLIENT );
                }
	            
	            return doCall( session, url, method, params, timeout, rawParams, type );

			} else {
				logger.info("RESPONSE OK ");

				accessTokenTries = 0;
				return conn;
			}
		}
	}

	private synchronized void getNewAccesToken(HttpSession session) throws OAuthSystemException, OAuthProblemException {
	    
	    String accessToken = getAccessToken(session);
	    String refreshToken;
	    
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
			refreshToken = oAuthResponse.getRefreshToken();

			Date expiresIn = new Date();

			Long responseExpiredIn = oAuthResponse.getExpiresIn();
			if(responseExpiredIn == null || responseExpiredIn == 0l ){
				responseExpiredIn = defaultExpiresIn;
			}
			
			expiresIn.setTime( expiresIn.getTime() + ( responseExpiredIn * 1000) );
			
			session.setAttribute(OAuth.OAUTH_BEARER_TOKEN, accessToken);
			session.setAttribute(OAuth.OAUTH_EXPIRES_IN, expiresIn);
			session.setAttribute(OAuth.OAUTH_REFRESH_TOKEN, refreshToken);

			logger.info("NEW TOKEN[" + accessToken + "] EXPIRES IN[" + expiresIn + "]");
			
		}
	}

	public void refreshToken( HttpServletRequest p_request, String refreshToken ) throws OAuthProblemException, OAuthSystemException, IOException {
		refreshToken( p_request.getSession(), refreshToken );
	}
	
	public void refreshToken( HttpSession p_session, String refreshToken ) throws OAuthProblemException, OAuthSystemException, IOException {
	    
		revokeToken(p_session);
		
		String accessToken = getAccessToken(p_session);
	    Date expiresIn = getExpiresIn(p_session);
	    logger.severe("OLD TOKEN[" + accessToken + "]"); 	
        String url = tokenLocation;        
        String query = "?grant_type=refresh_token&client_id="+applicationId+"&client_secret="+applicationSecret+"&refresh_token="+refreshToken;
        url += query;
        
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
	        
	
			conn.setRequestMethod( OAuth.HttpMethod.GET );
			conn.setDoOutput(true);
		
			conn.setConnectTimeout(connectionTimeout);
			Integer responseCode = conn.getResponseCode();
	        String resultado;
	        StringBuffer text = new StringBuffer();
			InputStreamReader in = new InputStreamReader((InputStream) conn.getContent(), "UTF8");
			BufferedReader buff = new BufferedReader(in);
			String line = buff.readLine();                
			while (line != null){
				text.append(line + "\n");
				line = buff.readLine();
			}             
			resultado = text.toString();
			
			logger.severe("The output of refresh token method is: "+resultado);
			
			JsonParser parser = new JsonParser();
			JsonElement jsonElement;
			
			if(parser.parse(resultado).isJsonObject()){
				//return json object
				jsonElement = parser.parse(resultado).getAsJsonObject();
				if( jsonElement.getAsJsonObject() != null && jsonElement.getAsJsonObject().get("access_token") != null && jsonElement.getAsJsonObject().get("access_token").getAsString() != null){
					accessToken = jsonElement.getAsJsonObject().get("access_token").getAsString();
				}
				expiresIn = new Date();
				Long responseExpiredIn;
				if( jsonElement.getAsJsonObject() != null && jsonElement.getAsJsonObject().get("expires_in") != null && jsonElement.getAsJsonObject().get("expires_in").getAsString() != null){		
					responseExpiredIn = jsonElement.getAsJsonObject().get("expires_in").getAsLong();
					if(responseExpiredIn == null || responseExpiredIn == 0l ){
						responseExpiredIn = defaultExpiresIn;
					}
				} else {
					responseExpiredIn = defaultExpiresIn;
				}
				if( jsonElement.getAsJsonObject() != null && jsonElement.getAsJsonObject().get("refresh_token") != null && jsonElement.getAsJsonObject().get("refresh_token").getAsString() != null){	
					refreshToken = jsonElement.getAsJsonObject().get("refresh_token").getAsString();
				}
				if( responseExpiredIn != null ){
					expiresIn.setTime( expiresIn.getTime() + ( responseExpiredIn * 1000) );				
				} else {
					expiresIn = null;
				}
				p_session.setAttribute(OAuth.OAUTH_BEARER_TOKEN, accessToken);
				p_session.setAttribute(OAuth.OAUTH_EXPIRES_IN, expiresIn);
				p_session.setAttribute(OAuth.OAUTH_REFRESH_TOKEN, refreshToken);
	
				logger.severe("NEW TOKEN[" + accessToken + "] EXPIRES IN[" + expiresIn + "]"); 	
				
				
			} 
	    
	}
	
	private void revokeToken( HttpSession session ) throws IOException {
		String accessToken = getAccessToken(session);
        String url = revokeUrl;
        
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
	        
	
			conn.setRequestMethod( OAuth.HttpMethod.POST );
			conn.setDoOutput(true);
			conn.setRequestProperty(OAuth.HeaderType.CONTENT_TYPE, OAuth.ContentType.URL_ENCODED);
		
			conn.setConnectTimeout(connectionTimeout);
			
			HashMap<String, String> params = new HashMap<String, String>(); 
			params.put("token", accessToken);
			
			OutputStream output = conn.getOutputStream();
			output.write( getPayload(params) );
			output.flush();
			output.close();
			
			Integer responseCode = conn.getResponseCode();
			logger.severe("The response code in the revoke token method is: "+responseCode);
		
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
