/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletResponse;

import org.assertj.core.api.Condition;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.LogoutResponseUnmarshaller;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidatorParameters;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.soap.SOAPClient;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.xml.ParserPool;

/**
 * Tests for {@link Saml2RelyingPartyInitiatedLogoutSuccessHandler}
 *
 * @author Josh Cummings
 */
public class Saml2RelyingPartyInitiatedLogoutSuccessHandlerTests {

	Saml2LogoutRequestResolver logoutRequestResolver = mock(Saml2LogoutRequestResolver.class);

	Saml2LogoutRequestRepository logoutRequestRepository = mock(Saml2LogoutRequestRepository.class);

	RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = mock(RelyingPartyRegistrationResolver.class);

	Saml2LogoutResponseValidator logoutResponseValidator = mock(Saml2LogoutResponseValidator.class);

	LogoutSuccessHandler logoutSuccessHandler = mock(LogoutSuccessHandler.class);

	SOAPClient soapClient = mock(SOAPClient.class);

	static LogoutResponse logoutResponse;

	Saml2RelyingPartyInitiatedLogoutSuccessHandler logoutRequestSuccessHandler = new Saml2RelyingPartyInitiatedLogoutSuccessHandler(
			this.logoutRequestResolver, this.relyingPartyRegistrationResolver, this.logoutSuccessHandler,
			this.logoutResponseValidator);

	@BeforeAll
	public static void beforeAll() throws Exception {
		OpenSamlInitializationService.initialize();
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		LogoutResponseUnmarshaller logoutResponseUnmarshaller = (LogoutResponseUnmarshaller) registry
				.getUnmarshallerFactory().getUnmarshaller(LogoutResponse.DEFAULT_ELEMENT_NAME);
		ParserPool parserPool = registry.getParserPool();
		ClassPathResource resource = new ClassPathResource("logout-response.xml");
		String response = null;
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream()))) {
			response = reader.lines().collect(Collectors.joining());
		}
		Document document = parserPool.parse(new ByteArrayInputStream(response.getBytes(StandardCharsets.UTF_8)));
		Element element = document.getDocumentElement();
		logoutResponse = (LogoutResponse) logoutResponseUnmarshaller.unmarshall(element);
	}

	@BeforeEach
	public void setUp() {
		this.logoutRequestSuccessHandler.setLogoutRequestRepository(this.logoutRequestRepository);
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void onLogoutSuccessWhenRedirectThenRedirectsToAssertingParty() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		Authentication authentication = authentication(registration);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest("request").build();
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/saml2/logout");
		request.setServletPath("/saml2/logout");
		MockHttpServletResponse response = new MockHttpServletResponse();
		given(this.logoutRequestResolver.resolve(any(), any())).willReturn(logoutRequest);
		this.logoutRequestSuccessHandler.onLogoutSuccess(request, response, authentication);
		String content = response.getHeader("Location");
		assertThat(content).contains(Saml2ParameterNames.SAML_REQUEST);
		assertThat(content).startsWith(registration.getAssertingPartyDetails().getSingleLogoutServiceLocation());
	}

	@Test
	public void onLogoutSuccessWhenPostThenPostsToAssertingParty() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full()
				.assertingPartyDetails((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.POST)).build();
		Authentication authentication = authentication(registration);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest("request").build();
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/saml2/logout");
		request.setServletPath("/saml2/logout");
		MockHttpServletResponse response = new MockHttpServletResponse();
		given(this.logoutRequestResolver.resolve(any(), any())).willReturn(logoutRequest);
		this.logoutRequestSuccessHandler.onLogoutSuccess(request, response, authentication);
		String content = response.getContentAsString();
		assertThat(content).contains(Saml2ParameterNames.SAML_REQUEST);
		assertThat(content).contains(registration.getAssertingPartyDetails().getSingleLogoutServiceLocation());
	}

	@Test
	public void onLogoutSuccessWhenSoapThenSoapToAssertingPartyThenValidateResponse() throws Exception {
		this.logoutRequestSuccessHandler.setSoapClient(soapClient);
		given(this.soapClient.send(any(XMLObject.class), any(), any())).willReturn(logoutResponse);
		given(this.logoutResponseValidator.validate(any(Saml2LogoutResponseValidatorParameters.class)))
				.willReturn(mock(Saml2LogoutValidatorResult.class));
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full()
				.assertingPartyDetails((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.SOAP)).build();
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(registration);
		Authentication authentication = authentication(registration);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(mock(LogoutRequest.class)).build();
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/saml2/logout");
		request.setServletPath("/saml2/logout");
		MockHttpServletResponse response = new MockHttpServletResponse();
		given(this.logoutRequestResolver.resolve(any(), any())).willReturn(logoutRequest);
		this.logoutRequestSuccessHandler.onLogoutSuccess(request, response, authentication);
		verify(logoutSuccessHandler).onLogoutSuccess(any(), any(), any());
	}

	@Test
	public void onLogoutSuccessWhenSoapThenSoapToAssertingPartyThenRelyingPartyRegistrationNotFound() throws Exception {
		this.logoutRequestSuccessHandler.setSoapClient(soapClient);
		given(this.soapClient.send(any(XMLObject.class), any(), any())).willReturn(logoutResponse);
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full()
				.assertingPartyDetails((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.SOAP)).build();
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(null);
		Authentication authentication = authentication(registration);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(mock(LogoutRequest.class)).build();
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/saml2/logout");
		request.setServletPath("/saml2/logout");
		MockHttpServletResponse response = new MockHttpServletResponse();
		given(this.logoutRequestResolver.resolve(any(), any())).willReturn(logoutRequest);
		this.logoutRequestSuccessHandler.onLogoutSuccess(request, response, authentication);
		verifyNoInteractions(logoutSuccessHandler);
		assertThat(response).is(new Condition<MockHttpServletResponse>(
				r -> r.getStatus() == HttpServletResponse.SC_BAD_REQUEST
				&& r.getErrorMessage().contains("relying_party_registration_not_found"),
		"relying_party_registration_not_found"));
	}

	@Test
	public void onLogoutSuccessWhenSoapThenSoapToAssertingPartyThenResponseNotInstanceOfLogoutResponse() throws Exception {
		this.logoutRequestSuccessHandler.setSoapClient(soapClient);
		given(this.soapClient.send(any(XMLObject.class), any(), any())).willReturn(mock(Response.class));
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full()
				.assertingPartyDetails((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.SOAP)).build();
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(registration);
		Authentication authentication = authentication(registration);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(mock(LogoutRequest.class)).build();
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/saml2/logout");
		request.setServletPath("/saml2/logout");
		MockHttpServletResponse response = new MockHttpServletResponse();
		given(this.logoutRequestResolver.resolve(any(), any())).willReturn(logoutRequest);
		this.logoutRequestSuccessHandler.onLogoutSuccess(request, response, authentication);
		verifyNoInteractions(logoutSuccessHandler);
		assertThat(response).is(new Condition<MockHttpServletResponse>(
				r -> r.getStatus() == HttpServletResponse.SC_BAD_REQUEST
				&& r.getErrorMessage().contains("malformed_response_data"),
		"malformed_response_data"));
	}

	@Test
	public void onLogoutSuccessWhenSoapThenSoapToAssertingPartyThenValidationFails() throws Exception {
		this.logoutRequestSuccessHandler.setSoapClient(soapClient);
		given(this.soapClient.send(any(XMLObject.class), any(), any())).willReturn(logoutResponse);
		given(this.logoutResponseValidator.validate(any(Saml2LogoutResponseValidatorParameters.class)))
				.willReturn(Saml2LogoutValidatorResult.withErrors(new Saml2Error("1", "error")).build());
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full()
				.assertingPartyDetails((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.SOAP)).build();
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(registration);
		Authentication authentication = authentication(registration);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(mock(LogoutRequest.class)).build();
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/saml2/logout");
		request.setServletPath("/saml2/logout");
		MockHttpServletResponse response = new MockHttpServletResponse();
		given(this.logoutRequestResolver.resolve(any(), any())).willReturn(logoutRequest);
		this.logoutRequestSuccessHandler.onLogoutSuccess(request, response, authentication);
		verifyNoInteractions(logoutSuccessHandler);
		assertThat(response).is(new Condition<MockHttpServletResponse>(
				r -> r.getStatus() == HttpServletResponse.SC_UNAUTHORIZED
				&& r.getErrorMessage().contains("error"),
		"error"));
	}

	private Saml2Authentication authentication(RelyingPartyRegistration registration) {
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user", new HashMap<>());
		principal.setRelyingPartyRegistrationId(registration.getRegistrationId());
		return new Saml2Authentication(principal, "response", new ArrayList<>());
	}

	@Test
	public void setSoapClienaWhenNullThenIllegalArgument() {
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> logoutRequestSuccessHandler.setSoapClient(null));
	}
}
