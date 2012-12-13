package com.igzcode.oauth2.provider;

public class OAuthDecision {

	private Boolean authorized;
	private int httpError;
	private String errorDescription;

	public OAuthDecision(Boolean p_authorized, int p_httpError, String p_errorDescription) {
		this.authorized = p_authorized;
		this.httpError = p_httpError;
		this.errorDescription = p_errorDescription;
	}
	public Boolean getAuthorized() {
		return this.authorized;
	}
	public void setAuthorized(Boolean p_authorized) {
		this.authorized = p_authorized;
	}
	public int getHttpError() {
		return this.httpError;
	}
	public void setHttpError(int p_httpError) {
		this.httpError = p_httpError;
	}
	public String getErrorDescription() {
		return this.errorDescription;
	}
	public void setErrorDescription(String p_errorDescription) {
		this.errorDescription = p_errorDescription;
	}


}
