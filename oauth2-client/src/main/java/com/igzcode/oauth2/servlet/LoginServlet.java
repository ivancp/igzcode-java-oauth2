package com.igzcode.oauth2.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.amber.oauth2.common.OAuth;

@SuppressWarnings("serial")
public class LoginServlet extends HttpServlet {
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		
		//at this point we have a valid accessToken in session, and we are receiving a valid login.
		
		resp.sendRedirect("index.jsp?access_token=" + req.getSession().getAttribute(OAuth.OAUTH_BEARER_TOKEN));
		
	}
    
}
