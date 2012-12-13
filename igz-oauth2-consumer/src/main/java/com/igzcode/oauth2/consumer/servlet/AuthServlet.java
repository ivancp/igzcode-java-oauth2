package com.igzcode.oauth2.consumer.servlet;


import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.common.OAuth;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;

import com.igzcode.oauth2.consumer.IgzOAuthClient;


public class AuthServlet extends HttpServlet {

	private static final long serialVersionUID = 2196476799561779355L;

	@Override
	protected void doGet(HttpServletRequest p_request, HttpServletResponse p_response) throws ServletException, IOException {
		try {

			OAuthClientRequest request = OAuthClientRequest
					.authorizationLocation( IgzOAuthClient.getAuthLocation() )
					.setClientId( IgzOAuthClient.getApplicationId() )
					.setRedirectURI( IgzOAuthClient.getRedirectUrl() )
					.setResponseType( OAuth.OAUTH_CODE )
					.buildQueryMessage();

			p_response.sendRedirect(request.getLocationUri());
			
		} catch (OAuthSystemException e) {
			e.printStackTrace();
		}
	}
}
