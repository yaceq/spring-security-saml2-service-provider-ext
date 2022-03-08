package org.springframework.security.saml2.soap;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.List;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.soap.client.http.HttpSOAPRequestParameters;
import org.opensaml.soap.soap11.Body;
import org.opensaml.soap.soap11.Envelope;
import org.opensaml.soap.soap11.impl.BodyBuilder;
import org.opensaml.soap.soap11.impl.EnvelopeBuilder;
import org.opensaml.soap.soap11.impl.EnvelopeMarshaller;
import org.opensaml.soap.soap11.impl.EnvelopeUnmarshaller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;

public class HttpSOAPClient implements SOAPClient {
	
	static {
		OpenSamlInitializationService.initialize();
	}
	
	private final Logger log = LoggerFactory.getLogger(HttpSOAPClient.class);

	private final ParserPool parserPool;
	
	private final EnvelopeMarshaller envelopeMarshaller;
	
	private final EnvelopeUnmarshaller envelopeUnmarshaller;
	
	private final EnvelopeBuilder envelopeBuilder;
	
	private final BodyBuilder bodyBuilder;
	
	public HttpSOAPClient() {
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.parserPool = registry.getParserPool();
		this.envelopeMarshaller = (EnvelopeMarshaller) registry.getMarshallerFactory()
				.getMarshaller(Envelope.DEFAULT_ELEMENT_NAME);
		this.envelopeUnmarshaller = (EnvelopeUnmarshaller) registry.getUnmarshallerFactory()
				.getUnmarshaller(Envelope.DEFAULT_ELEMENT_NAME);
		this.envelopeBuilder = (EnvelopeBuilder) registry.getBuilderFactory().getBuilder(Envelope.DEFAULT_ELEMENT_NAME);
		this.bodyBuilder = (BodyBuilder) registry.getBuilderFactory().getBuilder(Body.DEFAULT_ELEMENT_NAME);
	}
	
	@Override
	public XMLObject send(XMLObject envelope, String url, HttpSOAPRequestParameters params) {
		try (CloseableHttpClient client = this.createClient()) {
			HttpPost httpPost = createPostMethod(url, params, envelope);
			CloseableHttpResponse response = client.execute(httpPost);
	        final int code = response.getStatusLine().getStatusCode();
	        log.debug("Received HTTP status code of {} when POSTing SOAP message to {}", code, url);
	
	        if (code == HttpStatus.SC_OK) {
	            return processSuccessfulResponse(response);
	        }  else {
				throw new Saml2AuthenticationException(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Received " + code + " HTTP response status code from HTTP request to " + url));
	        }
		} catch (IOException e) {
			throw new Saml2AuthenticationException(new Saml2Error(Saml2ErrorCodes.INVALID_REQUEST, "Unable to send request"));
		}
	}
	
	private Envelope createEnvelope(XMLObject object) {
		Body body = this.bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(object);
		Envelope envelope = this.envelopeBuilder.buildObject();
		envelope.setBody(body);
		return envelope;
	}
	
    protected HttpPost createPostMethod(final String url,
    		HttpSOAPRequestParameters params, final XMLObject message) {
        log.debug("POSTing SOAP message to {}", url);

		HttpPost httpPost = new HttpPost(url);
		httpPost.setEntity(createRequestEntity(message));
					
        if (params != null && params.getSOAPAction() != null) {
        	httpPost.setHeader(HttpSOAPRequestParameters.SOAP_ACTION_HEADER, params.getSOAPAction());
        }

        return httpPost;
    }
	
	protected CloseableHttpClient createClient() {
		return HttpClients.createSystem();
	}
	
	protected HttpEntity createRequestEntity(XMLObject message) {
		if (!(message instanceof Envelope)) {
			message = createEnvelope(message);
		}
		try {
			Element element = envelopeMarshaller.marshall(message);
			String envelope =  SerializeSupport.nodeToString(element);
	        if (log.isDebugEnabled()) {
	            log.debug("Outbound SOAP message is:\n {}", envelope);
	        }
	        return new StringEntity(envelope);
		} catch (UnsupportedEncodingException | MarshallingException e) {
			throw new Saml2AuthenticationException(new Saml2Error(Saml2ErrorCodes.INVALID_REQUEST, "Invalid request message"), e);
		}
    }
	
    protected XMLObject processSuccessfulResponse(final HttpResponse httpResponse) {
        if (httpResponse.getEntity() == null) {
			throw new Saml2AuthenticationException(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Response does not contain body"));
        }
        try {
			return unmarshallResponse(httpResponse.getEntity().getContent());
		} catch (UnsupportedOperationException | IOException e) {
			throw new Saml2AuthenticationException(new Saml2Error(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, "Unable to read content of response"), e);
		}
    }

	private XMLObject unmarshallResponse(InputStream inputStream)  {
		Element element;
		try {
			element = parserPool.parse(inputStream).getDocumentElement();
	        if (log.isDebugEnabled()) {
				String responseStr =  SerializeSupport.nodeToString(element);
	            log.debug("Inbound SOAP message is:\n {}", responseStr);
	        }
			Envelope envelope = (Envelope) this.envelopeUnmarshaller.unmarshall(element);
			List<XMLObject> xmlObjects = envelope.getBody().getUnknownXMLObjects();
			if (xmlObjects.isEmpty()) {
				throw new Saml2AuthenticationException(new Saml2Error(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, "Envelope does not contain XML response"));
			} 
			return xmlObjects.get(0);
		} catch (XMLParserException | UnmarshallingException e) {
			throw new Saml2AuthenticationException(new Saml2Error(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, "Invalid response message"), e);
		}
	}

}
