package org.springframework.security.saml2.soap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

import org.assertj.core.api.Condition;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.impl.LogoutRequestUnmarshaller;
import org.opensaml.saml.saml2.core.impl.LogoutResponseUnmarshaller;
import org.opensaml.soap.client.http.HttpSOAPRequestParameters;
import org.opensaml.soap.soap11.Body;
import org.opensaml.soap.soap11.Envelope;
import org.opensaml.soap.soap11.impl.BodyBuilder;
import org.opensaml.soap.soap11.impl.EnvelopeBuilder;
import org.opensaml.soap.soap11.impl.EnvelopeMarshaller;
import org.opensaml.soap.soap11.impl.EnvelopeUnmarshaller;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;

public class HttpSOAPClientTests {

	static {
		OpenSamlInitializationService.initialize();
	}

	static XMLObjectProviderRegistry registry;
	static EnvelopeMarshaller envelopeMarshaller;
	static EnvelopeUnmarshaller envelopeUnmarshaller;
	static EnvelopeBuilder envelopeBuilder;
	static BodyBuilder bodyBuilder;
	static LogoutResponseUnmarshaller logoutResponseUnmarshaller;
	static LogoutRequestUnmarshaller logoutRequestUnmarshaller;
	static ParserPool parserPool;

	LogoutResponse logoutResponse;

	LogoutRequest logoutRequest;

	HttpSOAPClient soapClient = new HttpSOAPClient();

	@BeforeAll
	public static void beforeAll() throws Exception {
		OpenSamlInitializationService.initialize();

		registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		envelopeMarshaller = (EnvelopeMarshaller) registry.getMarshallerFactory()
				.getMarshaller(Envelope.DEFAULT_ELEMENT_NAME);
		envelopeUnmarshaller = (EnvelopeUnmarshaller) registry.getUnmarshallerFactory()
				.getUnmarshaller(Envelope.DEFAULT_ELEMENT_NAME);
		envelopeBuilder = (EnvelopeBuilder) registry.getBuilderFactory().getBuilder(Envelope.DEFAULT_ELEMENT_NAME);
		bodyBuilder = (BodyBuilder) registry.getBuilderFactory().getBuilder(Body.DEFAULT_ELEMENT_NAME);
		logoutResponseUnmarshaller = (LogoutResponseUnmarshaller) registry
				.getUnmarshallerFactory().getUnmarshaller(LogoutResponse.DEFAULT_ELEMENT_NAME);
		logoutRequestUnmarshaller = (LogoutRequestUnmarshaller) registry
				.getUnmarshallerFactory().getUnmarshaller(LogoutRequest.DEFAULT_ELEMENT_NAME);
		parserPool = registry.getParserPool();

	}

	@BeforeEach
	public void beforeEach() throws Exception {
		ClassPathResource resource = new ClassPathResource("logout-response.xml");
		String logout = null;
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream()))) {
			logout = reader.lines().collect(Collectors.joining());
		}
		Document document = parserPool.parse(new ByteArrayInputStream(logout.getBytes(StandardCharsets.UTF_8)));
		Element element = document.getDocumentElement();
		logoutResponse = (LogoutResponse) logoutResponseUnmarshaller.unmarshall(element);

		resource = new ClassPathResource("logout-request.xml");
		logout = null;
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream()))) {
			logout = reader.lines().collect(Collectors.joining());
		}
		document = parserPool.parse(new ByteArrayInputStream(logout.getBytes(StandardCharsets.UTF_8)));
		element = document.getDocumentElement();
		logoutRequest = (LogoutRequest) logoutRequestUnmarshaller.unmarshall(element);
	}

	@Test
	public void sendWhenStatus200ThenReturnResponse() throws MarshallingException, IOException {
		try (MockWebServer server = new MockWebServer()) {
			server.enqueue(new MockResponse().setBody(prepareResponse(logoutResponse)).setResponseCode(200));
			XMLObject soapResponse = this.soapClient.send(prepareRequest(logoutRequest), server.url("/").toString(),
					new HttpSOAPRequestParameters("action"));
			assertThat(soapResponse).isInstanceOf(LogoutResponse.class);
			LogoutResponse soapLogoutResponse = (LogoutResponse) soapResponse;
			assertThat(soapLogoutResponse.getID()).isEqualTo(logoutResponse.getID());
			assertThat(soapLogoutResponse.getInResponseTo()).isEqualTo(logoutResponse.getInResponseTo());
			assertThat(soapLogoutResponse.getIssueInstant()).isEqualTo(logoutResponse.getIssueInstant());
			assertThat(soapLogoutResponse.getIssuer().getValue()).isEqualTo(logoutResponse.getIssuer().getValue());
			assertThat(soapLogoutResponse.getStatus().getStatusCode().getValue())
					.isEqualTo(logoutResponse.getStatus().getStatusCode().getValue());
		}
	}

	@Test
	public void sendWhenStatusNot200ThenThrowException() throws MarshallingException, IOException {
		try (MockWebServer server = new MockWebServer()) {
			server.enqueue(new MockResponse().setResponseCode(500));
			XMLObject req = prepareRequest(logoutRequest);
			assertThatExceptionOfType(Saml2AuthenticationException.class)
					.isThrownBy(() -> this.soapClient.send(req, server.url("/").toString(), null))
					.withMessage("Received 500 HTTP response status code from HTTP request to "
							+ server.url("/").toString());
		}
	}

	@Test
	public void sendWhenStatus200ButNoBodyThenThrowException() throws MarshallingException, IOException {
		try (MockWebServer server = new MockWebServer()) {
			server.enqueue(new MockResponse().setResponseCode(200));
			XMLObject req = prepareRequest(logoutRequest);
			assertThatExceptionOfType(Saml2AuthenticationException.class)
					.isThrownBy(() -> this.soapClient.send(req, server.url("/").toString(), null))
					.is(new Condition<Saml2AuthenticationException>( //
							e -> e.getSaml2Error().getErrorCode().equals(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA) //
							&& e.getSaml2Error().getDescription().equals("Invalid response message"),//
						"Invalid XML"));
		}
	}

	@Test
	public void sendWhenStatus200ButEmptyEnvelopeThenThrowException() throws MarshallingException, IOException {
		try (MockWebServer server = new MockWebServer()) {
			server.enqueue(new MockResponse().setBody(prepareResponse(null)).setResponseCode(200));
			XMLObject req = prepareRequest(logoutRequest);
			assertThatExceptionOfType(Saml2AuthenticationException.class)
					.isThrownBy(() -> this.soapClient.send(req, server.url("/").toString(), null))
					.is(new Condition<Saml2AuthenticationException>( //
						e -> e.getSaml2Error().getErrorCode().equals(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA) //
							&& e.getSaml2Error().getDescription().equals("Envelope does not contain XML response"),//
						"Invalid XML"));
		}
	}

	private String prepareResponse(XMLObject object) throws MarshallingException {
		Body body = bodyBuilder.buildObject();
		body.getUnknownXMLObjects().add(object);
		Envelope envelope = envelopeBuilder.buildObject();
		envelope.setBody(body);
		Element element = envelopeMarshaller.marshall(envelope);
		return SerializeSupport.nodeToString(element);
	}

	private XMLObject prepareRequest(XMLObject object) throws MarshallingException {
		Body body = bodyBuilder.buildObject();
		body.getUnknownXMLObjects().add(object);
		Envelope envelope = envelopeBuilder.buildObject();
		envelope.setBody(body);
		return envelope;
	}
}
