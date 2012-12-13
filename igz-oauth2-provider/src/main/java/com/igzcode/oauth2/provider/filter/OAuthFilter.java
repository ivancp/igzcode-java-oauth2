package com.igzcode.oauth2.provider.filter;

import java.io.IOException;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.amber.oauth2.common.error.OAuthError;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.message.types.ParameterStyle;
import org.apache.amber.oauth2.rs.request.OAuthAccessResourceRequest;

import com.igzcode.oauth2.provider.IgzOAuthProvider;
import com.igzcode.oauth2.provider.OAuthDecision;
import com.igzcode.oauth2.provider.OAuthManager;

public class OAuthFilter implements Filter {

	protected static final Logger logger = Logger.getLogger(OAuthFilter.class.getName());

	private static final String TOKEN_DELIMITER = ",";
	private static final String RS_TOKENS = "HEADER";
	private static final ParameterStyle RS_TOKENS_DEFAULT = ParameterStyle.HEADER;

	private IgzOAuthProvider provider;

	private ParameterStyle[] parameterStyles;

	public void init(FilterConfig filterConfig) throws ServletException {
		logger.info("INIT OAuthFilter");

		this.provider = new IgzOAuthProvider();

		String parameterStylesString = RS_TOKENS;
		if (parameterStylesString == null || parameterStylesString.equals("")) {
			this.parameterStyles = new ParameterStyle[] {RS_TOKENS_DEFAULT};
		} else {
			String[] parameters = parameterStylesString.split(TOKEN_DELIMITER);
			if (parameters != null && parameters.length > 0) {
				this.parameterStyles = new ParameterStyle[parameters.length];
				for (int i = 0; i < parameters.length; i++) {
					ParameterStyle tempParameterStyle = ParameterStyle.valueOf(parameters[i]);
					if (tempParameterStyle != null) {
						this.parameterStyles[i] = tempParameterStyle;
					} else {
						throw new ServletException("Incorrect ParameterStyle: " + parameters[i]);
					}
				}
			}
		}
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest)request;
		HttpServletResponse httpResponse = (HttpServletResponse)response;

		logger.info("OAuthFilter doFilter PATH["+httpRequest.getPathInfo()+"]");

		try {
			OAuthAccessResourceRequest oauthRequest = new OAuthAccessResourceRequest(httpRequest, this.parameterStyles);

			String accessToken = oauthRequest.getAccessToken();

			logger.info("REQUEST WITH TOKEN["+accessToken+"]");

			final OAuthDecision decision = this.provider.validateRequest(accessToken, httpRequest);

			logger.info("OAUTH DECISION ISAUTH[" + decision.getAuthorized()+"] ERROR_DESC[" + decision.getErrorDescription()+"] CODE["+decision.getHttpError()+"]" );

			if( decision.getAuthorized() ) {
				logger.info("VALID REQUEST -> DO FILTER");
				chain.doFilter(request, response);
				return;
			} else {
				logger.info("UNAUTHORIZED_CLIENT ERROR" + OAuthError.TokenResponse.UNAUTHORIZED_CLIENT);
				throw OAuthProblemException.error(OAuthError.TokenResponse.UNAUTHORIZED_CLIENT).description(decision.getErrorDescription());
			}
		} catch (OAuthSystemException e1) {
			e1.printStackTrace();
			throw new ServletException(e1);
		} catch (OAuthProblemException e) {
			e.printStackTrace();
			OAuthManager.current().respondWithError(httpResponse, e);
		}
	}

	public void destroy() {

	}
}
