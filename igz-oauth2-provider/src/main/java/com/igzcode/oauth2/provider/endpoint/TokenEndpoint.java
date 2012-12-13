package com.igzcode.oauth2.provider.endpoint;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.amber.oauth2.as.issuer.MD5Generator;
import org.apache.amber.oauth2.as.issuer.OAuthIssuer;
import org.apache.amber.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.amber.oauth2.as.request.OAuthTokenRequest;
import org.apache.amber.oauth2.as.response.OAuthASResponse;
import org.apache.amber.oauth2.common.error.OAuthError;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.message.OAuthResponse;

import com.igzcode.oauth2.provider.OAuthManager;
import com.igzcode.oauth2.provider.client.ClientManager;
import com.igzcode.oauth2.provider.client.ClientVO;

public class TokenEndpoint extends HttpServlet {

	protected static final Logger logger = Logger.getLogger(TokenEndpoint.class.getName());

	private static final long serialVersionUID = 8026973802933283406L;

	@Override
	protected void doPost(
			HttpServletRequest request
			,HttpServletResponse response) throws ServletException, IOException {

		OAuthTokenRequest oauthRequest = null;

		OAuthIssuer oauthIssuerImpl = new OAuthIssuerImpl(new MD5Generator());

		try {
			oauthRequest = new OAuthTokenRequest(request);

			String clientId = oauthRequest.getClientId();
			ClientVO client = ClientManager.current().getClient(clientId);

			logger.info("TOKEN REQUEST CLIENT["+clientId+"]");

			if ( client == null ) {
				logger.info("INVALID CLIENT");
				throw OAuthProblemException.error(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT).description("Invalid Client");
			}
			else {
				String clientSecret = oauthRequest.getClientSecret();

				if ( client.getSecret().equals(clientSecret) && client.getClientId().equals(clientId) ) {
					logger.info("VALID CLIENT CREDENTIALS, STORE TOKEN");
					String accessToken = oauthIssuerImpl.accessToken();
					String refreshToken = oauthIssuerImpl.refreshToken();
					ClientManager.current().storeAccessToken(accessToken, client.getClientId(), "", OAuthManager.current().getExpires());

					OAuthResponse r = OAuthASResponse
							.tokenResponse(HttpServletResponse.SC_OK)
							.setAccessToken(accessToken)
							.setExpiresIn("3600")
							.setRefreshToken(refreshToken).buildJSONMessage();

					response.setStatus(r.getResponseStatus());
					response.getWriter().println(r.getBody());
				}
			}
		} catch (OAuthProblemException ex) {
			ex.printStackTrace();
			OAuthManager.current().respondWithError(response, ex);
		} catch (OAuthSystemException e) {
			e.printStackTrace();
		}
	}
}
