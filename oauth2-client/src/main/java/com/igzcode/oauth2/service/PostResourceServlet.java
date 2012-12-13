package com.igzcode.oauth2.service;


import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.utils.OAuthUtils;

import com.igzcode.oauth2.consumer.IgzOAuthClient;
import com.igzcode.oauth2.consumer.util.PropertiesUtil;



public class PostResourceServlet extends HttpServlet {

	private static final long serialVersionUID = -8286995466850336694L;

	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

		try {

			Map<String, String> map = new HashMap<String, String>();
			map.put("status", request.getParameter("status"));

			HttpURLConnection httpURLConnection = IgzOAuthClient.doPost( PropertiesUtil.getString("oauth2.protectedPostResource"), map );

			InputStream inputStream = null;
			if (httpURLConnection.getResponseCode() != 200) {
				inputStream = httpURLConnection.getErrorStream();
			} else {
				inputStream = httpURLConnection.getInputStream();
			}

			String responseBody = OAuthUtils.saveStreamAsString(inputStream);
			response.setStatus(httpURLConnection.getResponseCode());
			response.getWriter().print( responseBody );

		} catch (OAuthSystemException e) {
			e.printStackTrace();
		} catch (OAuthProblemException e) {
			e.printStackTrace();
		}
	}

}
