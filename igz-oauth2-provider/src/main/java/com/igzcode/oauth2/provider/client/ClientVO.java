package com.igzcode.oauth2.provider.client;


public class ClientVO {

	private String clientId;
	private String secret;
	private String redirectUri;

	public String getClientId() {
		return this.clientId;
	}
	public void setClientId(String p_clientId) {
		this.clientId = p_clientId;
	}
	public String getSecret() {
		return this.secret;
	}
	public void setSecret(String p_pwd) {
		this.secret = p_pwd;
	}
	public String getRedirectUri() {
		return this.redirectUri;
	}
	public void setRedirectUri(String p_redirectUri) {
		this.redirectUri = p_redirectUri;
	}
}
