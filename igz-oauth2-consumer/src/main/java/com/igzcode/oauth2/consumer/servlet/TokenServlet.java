package com.igzcode.oauth2.consumer.servlet;

import java.io.IOException;
import java.util.Date;

import javax.servlet.ServletConfig;
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
    
    private IgzOAuthClient igzOAuthClient;

    public void init(ServletConfig config) throws ServletException {
        
        String properties = config.getInitParameter("oauth2properties");
        if ( properties == null ) {
            properties = "oauth2.properties";
        }
        
        igzOAuthClient = new IgzOAuthClient(properties);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        try {
            OAuthAuthzResponse oar = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            String code = oar.getCode();

            OAuthClientRequest oautReq = OAuthClientRequest.tokenLocation(igzOAuthClient.getTokenLocation())
                    .setGrantType(GrantType.AUTHORIZATION_CODE).setClientId(igzOAuthClient.getApplicationId())
                    .setClientSecret(igzOAuthClient.getApplicationSecret()).setRedirectURI(igzOAuthClient.getRedirectUrl()).setCode(code)
                    .buildBodyMessage();

            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthAccessTokenResponse oAuthResponse = oAuthClient.accessToken(oautReq);

            String accessToken = oAuthResponse.getAccessToken();
            
            Date expiresIn = null;
            Long expiresL = oAuthResponse.getExpiresIn();

            if (expiresL != null) {
                expiresIn = new Date();
                expiresIn.setTime(expiresIn.getTime() + (oAuthResponse.getExpiresIn() * 1000));
            }

            request.getSession().setAttribute(OAuth.OAUTH_BEARER_TOKEN, accessToken);
            request.getSession().setAttribute(OAuth.OAUTH_EXPIRES_IN, expiresIn);

            response.sendRedirect(igzOAuthClient.getLoginEndPoint());

        } catch (OAuthProblemException e) {
            e.printStackTrace();
        } catch (OAuthSystemException e) {
            e.printStackTrace();
        }

    }
}
