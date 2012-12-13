package com.igzcode.oauth2.provider.endpoint;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.amber.oauth2.as.issuer.MD5Generator;
import org.apache.amber.oauth2.as.issuer.OAuthIssuer;
import org.apache.amber.oauth2.as.issuer.OAuthIssuerImpl;
import org.apache.amber.oauth2.as.request.OAuthAuthzRequest;
import org.apache.amber.oauth2.as.response.OAuthASResponse;
import org.apache.amber.oauth2.common.error.OAuthError;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.message.OAuthResponse;

import com.igzcode.oauth2.provider.OAuthManager;
import com.igzcode.oauth2.provider.client.ClientManager;
import com.igzcode.oauth2.provider.client.ClientVO;

public class AuthEndpoint extends HttpServlet {

	private static final long serialVersionUID = 926368659810135614L;

	@Override
	protected void doGet(HttpServletRequest request,HttpServletResponse response) throws ServletException, IOException {
		OAuthResponse oauthResponse;
		try {

			OAuthAuthzRequest oauthRequest = new OAuthAuthzRequest(request);

			ClientVO client = ClientManager.current().getClient(oauthRequest.getClientId());
			if ( client == null ) {
				throw OAuthProblemException.error(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT).description("Invalid Client");
			}
			else {
				OAuthIssuer oauthIssuerImpl = new OAuthIssuerImpl(new MD5Generator());

				// build OAuth response
				oauthResponse = OAuthASResponse
						.authorizationResponse(request, HttpServletResponse.SC_FOUND)
						.setCode(oauthIssuerImpl.authorizationCode())
						.location(client.getRedirectUri())
						.buildQueryMessage();

				response.sendRedirect(oauthResponse.getLocationUri());
			}

		} catch (OAuthProblemException ex) {
			OAuthManager.current().respondWithError(response, ex);
		} catch (OAuthSystemException e) {
			e.printStackTrace();
		}
	}
}
