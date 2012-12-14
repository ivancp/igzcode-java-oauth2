package com.igzcode.oauth2.consumer.servlet;


import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.amber.oauth2.client.OAuthClient;
import org.apache.amber.oauth2.client.URLConnectionClient;
import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.amber.oauth2.client.response.OAuthAuthzResponse;
import org.apache.amber.oauth2.common.OAuth;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.message.types.GrantType;

import com.igzcode.oauth2.consumer.IgzOAuthClient;


public class TokenServlet extends HttpServlet {

	private static final long serialVersionUID = 252800141251573580L;

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		try {
			System.out.println( "TokenServlet" );
			
			OAuthAuthzResponse oar = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
			String code = oar.getCode();

			OAuthClientRequest oautReq = OAuthClientRequest
					.tokenLocation(IgzOAuthClient.getTokenLocation())
					.setGrantType(GrantType.AUTHORIZATION_CODE)
					.setClientId(IgzOAuthClient.getApplicationId())
					.setClientSecret(IgzOAuthClient.getApplicationSecret())
					.setRedirectURI(IgzOAuthClient.getRedirectUrl())
					.setCode(code)
					.buildBodyMessage();

			OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
			OAuthAccessTokenResponse oAuthResponse = oAuthClient.accessToken(oautReq);

			String accessToken = oAuthResponse.getAccessToken();
			Long expiresIn = oAuthResponse.getExpiresIn();

			request.getSession().setAttribute(OAuth.OAUTH_BEARER_TOKEN, accessToken);
			request.getSession().setAttribute(OAuth.OAUTH_EXPIRES_IN, expiresIn);

			IgzOAuthClient.setAccessToken( accessToken );
			
			response.sendRedirect( IgzOAuthClient.getLoginEndPoint() );

		} catch (OAuthProblemException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (OAuthSystemException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
}
