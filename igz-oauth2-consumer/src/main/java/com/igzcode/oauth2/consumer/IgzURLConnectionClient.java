package com.igzcode.oauth2.consumer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.Map;

import org.apache.amber.oauth2.client.URLConnectionClient;
import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.client.response.OAuthClientResponse;
import org.apache.amber.oauth2.client.response.OAuthClientResponseFactory;
import org.apache.amber.oauth2.common.OAuth;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.utils.OAuthUtils;

public class IgzURLConnectionClient extends URLConnectionClient {

	private Integer timeout = 5000;

	public IgzURLConnectionClient() {
		super();
	}

	public IgzURLConnectionClient(Integer timeout) {
		super();
		this.timeout = timeout;
	}

	@Override
	public <T extends OAuthClientResponse> T execute(OAuthClientRequest request, Map<String, String> headers, String requestMethod, Class<T> responseClass) throws OAuthSystemException,
			OAuthProblemException {

		String responseBody = null;
		URLConnection c = null;
		int responseCode = 0;
		try {
			URL url = new URL(request.getLocationUri());

			c = url.openConnection();
			responseCode = -1;
			if (c instanceof HttpURLConnection) {
				HttpURLConnection httpURLConnection = (HttpURLConnection) c;
				httpURLConnection.setConnectTimeout(timeout);

				if (headers != null && !headers.isEmpty()) {
					for (Map.Entry<String, String> header : headers.entrySet()) {
						httpURLConnection.addRequestProperty(header.getKey(), header.getValue());
					}
				}

				if (!OAuthUtils.isEmpty(requestMethod)) {
					httpURLConnection.setRequestMethod(requestMethod);
					if (requestMethod.equals(OAuth.HttpMethod.POST)) {
						httpURLConnection.setDoOutput(true);
						OutputStream ost = httpURLConnection.getOutputStream();
						PrintWriter pw = new PrintWriter(ost);
						pw.print(request.getBody());
						pw.flush();
						pw.close();
					}
				} else {
					httpURLConnection.setRequestMethod(OAuth.HttpMethod.GET);
				}

				httpURLConnection.connect();

				InputStream inputStream;
				responseCode = httpURLConnection.getResponseCode();
				if (responseCode == 400) {
					inputStream = httpURLConnection.getErrorStream();
				} else {
					inputStream = httpURLConnection.getInputStream();
				}

				responseBody = OAuthUtils.saveStreamAsString(inputStream);
			}
		} catch (IOException e) {
			throw new OAuthSystemException(e);
		}

		return OAuthClientResponseFactory.createCustomResponse(responseBody, c.getContentType(), responseCode, responseClass);
	}

	@Override
	public void shutdown() {
		// Nothing to do here
	}

	public Integer getTimeout() {
		return timeout;
	}

	public void setTimeout(Integer timeout) {
		this.timeout = timeout;
	}

}
