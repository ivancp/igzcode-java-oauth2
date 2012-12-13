package com.igzcode.oauth2.res;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class GetProtectedResource extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = 926368659810135614L;

	@Override
	protected void doGet(HttpServletRequest request,HttpServletResponse response) throws ServletException, IOException {
		String param = request.getParameter("status");
		response.getWriter().print("PROTECTED RESOURCE 1 " + param );
	}

}
