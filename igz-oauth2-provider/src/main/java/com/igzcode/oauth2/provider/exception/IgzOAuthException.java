package com.igzcode.oauth2.provider.exception;

public class IgzOAuthException extends Exception {

	private static final long serialVersionUID = 3285962257930128369L;

	public IgzOAuthException() {
	}

	public IgzOAuthException(String p_message) {
		super(p_message);
	}

	public IgzOAuthException(Throwable p_cause) {
		super(p_cause);
	}

	public IgzOAuthException(String p_message, Throwable p_cause) {
		super(p_message, p_cause);
	}

}
