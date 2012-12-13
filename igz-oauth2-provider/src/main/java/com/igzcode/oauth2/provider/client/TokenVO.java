package com.igzcode.oauth2.provider.client;

import java.util.Date;

public class TokenVO {

	private String id;
	private String clientId;
	private Date expires;
	private String scope;
	private String authCode;



	public String getId() {
		return this.id;
	}

	public void setId(String p_id) {
		this.id = p_id;
	}

	public String getClientId() {
		return this.clientId;
	}

	public void setClientId(String p_clientId) {
		this.clientId = p_clientId;
	}

	public Date getExpires() {
		return this.expires;
	}

	public void setExpires(Date p_expires) {
		this.expires = p_expires;
	}

	public String getScope() {
		return this.scope;
	}

	public void setScope(String p_scope) {
		this.scope = p_scope;
	}

	public String getAuthCode() {
		return this.authCode;
	}

	public void setAuthCode(String p_AuthCode) {
		this.authCode = p_AuthCode;
	}
}
