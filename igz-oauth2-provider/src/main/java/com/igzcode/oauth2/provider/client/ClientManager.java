package com.igzcode.oauth2.provider.client;

import java.io.File;
import java.util.Date;
import java.util.HashMap;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.NodeList;

import com.igzcode.oauth2.provider.exception.IgzOAuthException;


public class ClientManager {

	static private ClientManager current;

	static synchronized public ClientManager current () {
		if ( current == null ) {
			try {
				current = new ClientManager();
			} catch (IgzOAuthException e) {
				e.printStackTrace();
			}
		}
		return current;
	}

	private HashMap<String, ClientVO> clients;
	private HashMap<String, TokenVO> tokens;
	private HashMap<String, String> refreshTokens; // TODO Test it

	private Document doc;
	private Transformer transformer;
	private StreamResult result;
	private DOMSource source;

	private ClientManager () throws IgzOAuthException {
		try {
			this.transformer = TransformerFactory.newInstance().newTransformer();
			DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
			File clientFile = new File(ClientManager.class.getClassLoader().getResource("oauth2_clients.xml").toURI());

			DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
			this.doc = docBuilder.parse(clientFile);
			this.source = new DOMSource(this.doc);
			this.result = new StreamResult(clientFile);

			this.loadClients();

			this.tokens = new HashMap<String, TokenVO>();
			this.refreshTokens = new HashMap<String, String>();
		} catch (Exception e) {
			e.printStackTrace();
			throw new IgzOAuthException("error reading oauth2_clients.xml");
		}
	}

	private void loadClients() {
		this.clients = new HashMap<String, ClientVO>();

		NodeList clients = this.doc.getElementsByTagName("client");
		ClientVO client;
		NamedNodeMap attrs;
		for ( int i=0; i < clients.getLength(); i++ ) {
			attrs = clients.item(i).getAttributes();

			client = new ClientVO();
			client.setClientId( attrs.getNamedItem("id").getNodeValue() );
			client.setSecret( attrs.getNamedItem("pwd").getNodeValue() );
			client.setRedirectUri( attrs.getNamedItem("uri").getNodeValue() );

			this.clients.put(client.getClientId(), client);
		}
	}

	synchronized public void save (String p_id, String p_pw, String p_uri) throws ParserConfigurationException, TransformerException {
		Element client = this.doc.createElement("client");
		client.setAttribute("id", p_id);
		client.setAttribute("pwd", p_pw);
		client.setAttribute("uri", p_uri);

		this.doc.getFirstChild().appendChild(client);

		this.transformer.transform(this.source, this.result);
	}

	public Boolean authCredentials (String p_clientId, String p_secret) {
		Boolean validClient = false;

		if ( p_clientId != null && p_clientId != "" && p_secret != null && p_secret != "" ) {

			ClientVO client = this.clients.get(p_clientId);
			if ( client != null ) {
				validClient = client.getSecret().equals(p_secret);
			}
		}
		return validClient;
	}

	public void storeRefreshToken ( String p_refreshToken, String p_clientId ) {
		this.refreshTokens.put(p_refreshToken, p_clientId); // TODO Test it
	}

	public void storeAccessToken ( String p_accessToken, String p_clientId, String p_scope, Long p_expiresIn ) {

		Date expireDate = new Date();
		expireDate.setTime( expireDate.getTime() + (p_expiresIn * 1000) );

		TokenVO token = new TokenVO();
		token.setId(p_accessToken);
		token.setClientId(p_clientId);
		token.setExpires(expireDate);
		token.setClientId(p_clientId);
		token.setScope(p_scope);
		this.tokens.remove(p_accessToken);
		this.tokens.put(p_accessToken, token);

	}

	public ClientVO getClient ( String p_clientId ) {
		return this.clients.get(p_clientId);
	}

	public TokenVO getToken ( String p_tokenId ) {
		return this.tokens.get(p_tokenId);
	}


	// TODO Test it
	public ClientVO getClientByRefreshToken ( String p_refreshToken ) {
		String clientId = this.refreshTokens.get(p_refreshToken);
		return this.clients.get(clientId);
	}
}
