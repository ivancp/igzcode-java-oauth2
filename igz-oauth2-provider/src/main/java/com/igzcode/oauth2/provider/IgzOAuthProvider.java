package com.igzcode.oauth2.provider;

import java.util.Date;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.amber.oauth2.common.error.OAuthError;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;

import com.igzcode.oauth2.provider.client.ClientManager;
import com.igzcode.oauth2.provider.client.TokenVO;
import com.igzcode.oauth2.provider.endpoint.TokenEndpoint;

public class IgzOAuthProvider {

	protected static final Logger logger = Logger.getLogger(TokenEndpoint.class.getName());

	public OAuthDecision validateRequest(String p_token, HttpServletRequest p_req) throws OAuthProblemException {
		Boolean authorized = false;
		String errorDescription = "";
		TokenVO storedToken = null;

		storedToken = ClientManager.current().getToken(p_token);

		if ( storedToken != null ) {
			Date expires =  storedToken.getExpires();
			if ( expires.after( new Date()) ){
				authorized = true;
			} else {
				logger.info("IgzOAuthProvider ERROR["+OAuthError.ResourceResponse.EXPIRED_TOKEN+"]");
				errorDescription = OAuthError.ResourceResponse.EXPIRED_TOKEN;
			}
		} else {
			logger.info("IgzOAuthProvider ERROR["+OAuthError.ResourceResponse.INVALID_TOKEN+"]");
			errorDescription = OAuthError.ResourceResponse.INVALID_TOKEN;
		}
		logger.info("IgzOAuthProvider ISAUTH["+authorized+"]");
		OAuthDecision decision = new OAuthDecision(authorized, (authorized ? HttpServletResponse.SC_UNAUTHORIZED : HttpServletResponse.SC_ACCEPTED ) , errorDescription);
		return decision;
	}
}