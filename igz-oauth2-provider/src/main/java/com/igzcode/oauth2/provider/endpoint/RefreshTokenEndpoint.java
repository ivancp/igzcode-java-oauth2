package com.igzcode.oauth2.provider.endpoint;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.igzcode.oauth2.provider.client.ClientManager;

public class RefreshTokenEndpoint extends HttpServlet {


	private static final long serialVersionUID = 8026973802933283406L;

	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		// TODO


		String refreshToken = request.getParameter("t");

		ClientManager.current().getClientByRefreshToken(refreshToken);

	}
}
