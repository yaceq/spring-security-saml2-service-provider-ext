package org.springframework.security.saml2.soap;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.soap.client.http.HttpSOAPRequestParameters;

public interface SOAPClient {

	XMLObject send(XMLObject envelope, String url, HttpSOAPRequestParameters params);

}
