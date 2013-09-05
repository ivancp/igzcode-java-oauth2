package com.igzcode.oauth2.consumer;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
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

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
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
	private static final String DEFAULT_EXPIRES_IN = "oauth2.defaultexpiresin";
	private static final String CONNECTION_TIMEOUT = "oauth2.connectionTimeout";
	private static final String UPDATE_TOKEN_URL = "oauth2.updateToken";
	
	private static final String USER_ID = "USER_ID";
	private static final String DEFAULT_DATE_FORMAT = "yyyy-MM-dd HH:mm:ss.S";
	
	private static final Charset CHARSET = Charset.forName("UTF-8");
	

	private static final String ENCODING = "UTF-8";
	private static final String HTTP_PATCH = "PATCH";

	private String grantType;
	private String applicationId;
	private String applicationSecret;
	private String redirectUrl;
	private String tokenLocation;
	private String authLocation;
	private Long defaultExpiresIn;
	private Integer connectionTimeout;
	
	private String authServletPath;
	private String loginEndPoint;
	private String updateTokenUrl;

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
	    updateTokenUrl = propertiesUtil.getString(UPDATE_TOKEN_URL);
	    
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
	
	public Long getDefaultExpiresIn() {
		return defaultExpiresIn;
	}

	public void setDefaultExpiresIn(Long defaultExpiresIn) {
		this.defaultExpiresIn = defaultExpiresIn;
	}

	public Date getExpiresIn(HttpServletRequest p_request) {
	    return (Date) p_request.getSession().getAttribute(OAuth.OAUTH_EXPIRES_IN);
	}
	
	public String getAccessToken(HttpServletRequest p_request) {
	    return (String) p_request.getSession().getAttribute(OAuth.OAUTH_BEARER_TOKEN);
	    
	}
	
	public String getRefreshToken(HttpServletRequest p_request) {
	    return (String) p_request.getSession().getAttribute(OAuth.OAUTH_REFRESH_TOKEN);
	    
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

	public Integer getConnectionTimeout() {
		return connectionTimeout;
	}

	public void setConnectionTimeout(Integer connectionTimeout) {
		this.connectionTimeout = connectionTimeout;
	}

	public HttpURLConnection doGet ( String p_url, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.GET, null, null, null, null );
	}

	public HttpURLConnection doGet ( String p_url, int timeout, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.GET, null, timeout, null, null );
	}

	public HttpURLConnection doPost ( String p_url, Map<String, String> p_params, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.POST, p_params, null, null, null );
	}
	public HttpURLConnection doPost ( String p_url, Map<String, String> p_params, int timeout, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.POST, p_params, timeout, null, null );
	}

	public HttpURLConnection doPost ( String p_url, String rawParams, int timeout, String type, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
	    return doCall( req, p_url, OAuth.HttpMethod.POST, null, timeout, rawParams, type );
	}
	
	public HttpURLConnection doPost ( String p_url, String rawParams, String type, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
	    return doCall( req, p_url, OAuth.HttpMethod.POST, null, null, rawParams, type );
	}

	public HttpURLConnection doPut ( String p_url, Map<String, String> p_params, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.PUT, p_params, null, null, null );
	}

	public HttpURLConnection doPut ( String p_url, Map<String, String> p_params, int timeout, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.PUT, p_params, timeout, null, null );
	}
	
	public HttpURLConnection doPatch ( String p_url, Map<String, String> p_params, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
	    return doCall( req, p_url, HTTP_PATCH, p_params, null, null, null );
	}
	
	public HttpURLConnection doPatch ( String p_url, Map<String, String> p_params, int timeout, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
	    return doCall( req, p_url, HTTP_PATCH, p_params, timeout, null, null );
	}
	
	public HttpURLConnection doPatch ( String p_url, String rawParams, int timeout, String type, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
        return doCall( req, p_url, HTTP_PATCH, null, timeout, rawParams, type );
    }
	
	public HttpURLConnection doPatch ( String p_url, String rawParams, String type, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
        return doCall( req, p_url, HTTP_PATCH, null, null, rawParams, type );
    }

	public HttpURLConnection doDelete ( String p_url, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.DELETE, null, null, null, null );
	}
	public HttpURLConnection doDelete ( String p_url, int timeout, HttpServletRequest req ) throws IOException, OAuthSystemException, OAuthProblemException {
		return doCall( req, p_url, OAuth.HttpMethod.DELETE, null, timeout, null, null );
	}

	private HttpURLConnection doCall ( HttpServletRequest req, String url, String method, Map<String, String> params, Integer timeout, String rawParams, String type ) throws IOException, OAuthSystemException, OAuthProblemException {

	    Date expiresIn = getExpiresIn(req);
	    String accessToken = getAccessToken(req);
	    Date date = new Date();
	    
		// Check if access token is null or has been expired
		if ( accessToken == null ) {
		    logger.info("ACCESS TOKEN NULL OR EXPIRED accesToken[" + accessToken + "]");
		    
			accessToken = null;
			
			if( GrantType.CLIENT_CREDENTIALS.toString().equals( getGrantType() )) {
				getNewAccesToken(req);
				
				return doCall( req, url, method, params, timeout, rawParams, type );
			} else if(  GrantType.AUTHORIZATION_CODE.toString().equals( getGrantType() ) ) {
				 throw OAuthProblemException.error(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT).description( OAuthError.TokenResponse.UNAUTHORIZED_CLIENT );
			} else {
				getNewAccesToken(req);
				
				return doCall( req, url, method, params, timeout, rawParams, type );
			}

		} else if( expiresIn != null && new Date().getTime() >= expiresIn.getTime() ) {
			
			//TODO: call refreshToken			
			refreshToken(req);
			return doCall( req, url, method, params, timeout, rawParams, type );
			
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

				req.getSession().setAttribute(OAuth.OAUTH_BEARER_TOKEN, null);
	            req.getSession().setAttribute(OAuth.OAUTH_EXPIRES_IN, null);
				req.getSession().setAttribute(OAuth.OAUTH_REFRESH_TOKEN, null);
	            
	            if ( GrantType.CLIENT_CREDENTIALS.toString().equals( getGrantType() ) ) {
                    getNewAccesToken(req);
                } else if(  GrantType.AUTHORIZATION_CODE.toString().equals( getGrantType() ) ) {
                    throw OAuthProblemException.error(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT).description( OAuthError.TokenResponse.UNAUTHORIZED_CLIENT );
                }
	            
	            return doCall( req, url, method, params, timeout, rawParams, type );

			} else {
				logger.info("RESPONSE OK ");

				accessTokenTries = 0;
				return conn;
			}
		}
	}
	
	private synchronized void refreshToken(HttpServletRequest req) throws OAuthProblemException, OAuthSystemException {
	    String accessToken = getAccessToken(req);
	    Date expiresIn = getExpiresIn(req);
	    String refreshToken = getRefreshToken(req);
	    
	    // if expiresIn and defaultExpiresIn is null request new accessToken 
	    if ( expiresIn == null && defaultExpiresIn == null ){
	    	accessToken = null;
	    	return;
	    }
	    
	    // Due to synchronized method, we must check if an call has updated the access token value before
	    if ( expiresIn != null && new Date().getTime() < expiresIn.getTime() ) {	        
	    	return;
	    }
	    
	    accessTokenTries ++;
        if( accessTokenTries > 3 ) {
            logger.info("GET NEW ACCESS TOKEN: ATTEMPTS EXCEEDED");
            throw OAuthProblemException.error(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT).description( OAuthError.TokenResponse.INVALID_CLIENT );
        }
        
        String url = tokenLocation;        
        String query = "?grant_type=refresh_token&client_id="+applicationId+"&client_secret="+applicationSecret+"&refresh_token="+refreshToken;
        url += query;
        try{
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
	
				expiresIn.setTime( expiresIn.getTime() + ( responseExpiredIn * 1000) );
				
				req.getSession().setAttribute(OAuth.OAUTH_BEARER_TOKEN, accessToken);
				req.getSession().setAttribute(OAuth.OAUTH_EXPIRES_IN, expiresIn);
				req.getSession().setAttribute(OAuth.OAUTH_REFRESH_TOKEN, refreshToken);
				
				try{
					Long userId =  (Long)req.getSession().getAttribute(USER_ID);
					updateToken(userId, accessToken, refreshToken, expiresIn);
				} catch( Exception e ){
					logger.severe("Update token Error \n"+e.getMessage());
				}
	
				logger.info("NEW TOKEN[" + accessToken + "] EXPIRES IN[" + expiresIn + "]"); 	
				
				
			} 
        } catch (IOException e){
			return;
		} 
	    
	}
	
	private void updateToken(Long userId, String accessToken, String refreshToken, Date expiresIn){
		
		try {
			HttpURLConnection conn = (HttpURLConnection) new URL(updateTokenUrl+"/"+userId).openConnection();

			conn.setRequestProperty(OAuth.HeaderType.CONTENT_TYPE, OAuth.ContentType.URL_ENCODED + ";charset="+ENCODING);
			conn.setRequestProperty("Accept-Charset", ENCODING);
			
			conn.setRequestMethod( OAuth.HttpMethod.PUT );
			conn.setDoOutput(true);
		
			HashMap<String, String> params = new HashMap<String,String>();
			params.put("a", accessToken);
			params.put("r", refreshToken);
			
			if(expiresIn != null){
			
			SimpleDateFormat dateFormat = new SimpleDateFormat(DEFAULT_DATE_FORMAT);
			String sExpiresIn = dateFormat.format(expiresIn);
			params.put("e", sExpiresIn);
			
			}
			
			OutputStream output = conn.getOutputStream();
			output.write( getPayload(params) );
			output.flush();
			output.close();
			
			conn.setConnectTimeout(connectionTimeout);
			Integer responseCode = conn.getResponseCode();
			logger.severe(responseCode+"");
			
		} catch (MalformedURLException e) {
			logger.severe("The updateToken url is wrong \n"+e.getMessage());
		} catch (IOException e) {
			logger.severe("Error connectin with the server in updateToken \n"+e.getMessage());
		}
		
	}

	private synchronized void getNewAccesToken(HttpServletRequest req) throws OAuthSystemException, OAuthProblemException {
	    
	    String accessToken = getAccessToken(req);
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
			
			req.getSession().setAttribute(OAuth.OAUTH_BEARER_TOKEN, accessToken);
			req.getSession().setAttribute(OAuth.OAUTH_EXPIRES_IN, expiresIn);
			req.getSession().setAttribute(OAuth.OAUTH_REFRESH_TOKEN, refreshToken);

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
