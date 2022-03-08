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

package org.springframework.security.saml2.provider.service.servlet.filter;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.authentication.TestSaml2AuthenticationTokens;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2ArtifactAuthenticationTokenConverter;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class Saml2WebSsoAuthenticationFilterTests {

	private Saml2WebSsoAuthenticationFilter filter;

	private RelyingPartyRegistrationRepository repository;

	private MockHttpServletRequest request;

	private HttpServletResponse response = new MockHttpServletResponse();

	private AuthenticationManager authenticationManager = mock(AuthenticationManager.class);

	@BeforeEach
	public void setup() {
		this.repository = mock(RelyingPartyRegistrationRepository.class);
		this.filter = new Saml2WebSsoAuthenticationFilter(this.repository);
		this.request = new MockHttpServletRequest();
		this.request.setPathInfo("/login/saml2/sso/idp-registration-id");
	}

	@Test
	public void constructingFilterWithMissingRegistrationIdVariableThenThrowsException() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(
				() -> this.filter = new Saml2WebSsoAuthenticationFilter(this.repository, "/url/missing/variable"))
				.withMessage("filterProcessesUrl must contain a {registrationId} match variable");
	}

	@Test
	public void constructingFilterWithValidRegistrationIdVariableThenSucceeds() {
		this.filter = new Saml2WebSsoAuthenticationFilter(this.repository, "/url/variable/is/present/{registrationId}");
	}

	@Test
	public void constructingFilterWithMissingRegistrationIdVariableAndCustomAuthenticationConverterThenSucceeds() {
		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		AuthenticationConverter artifactAuthenticationConverter = mock(AuthenticationConverter.class);
		this.filter = new Saml2WebSsoAuthenticationFilter(authenticationConverter, artifactAuthenticationConverter, "/url/missing/variable");
	}

	@Test
	public void requiresAuthenticationWhenSamlResponseAndHappyPathThenReturnsTrue() {
		this.request.setParameter(Saml2ParameterNames.SAML_RESPONSE, "xml-data-goes-here");
		Assertions.assertTrue(this.filter.requiresAuthentication(this.request, this.response));
	}

	@Test
	public void requiresAuthenticationWhenSamlArtHappyPathThenReturnsTrue() {
		this.request.setParameter(Saml2ParameterNames.SAML_ART, "samlart");
		Assertions.assertTrue(this.filter.requiresAuthentication(this.request, this.response));
	}
	
	@Test
	public void requiresAuthenticationWhenSamlResponseAndCustomProcessingUrlThenReturnsTrue() {
		this.filter = new Saml2WebSsoAuthenticationFilter(this.repository, "/some/other/path/{registrationId}");
		this.request.setPathInfo("/some/other/path/idp-registration-id");
		this.request.setParameter(Saml2ParameterNames.SAML_RESPONSE, "xml-data-goes-here");
		Assertions.assertTrue(this.filter.requiresAuthentication(this.request, this.response));
	}

	@Test
	public void requiresAuthenticationWhenSamlArtAndCustomProcessingUrlThenReturnsTrue() {
		this.filter = new Saml2WebSsoAuthenticationFilter(this.repository, "/some/other/path/{registrationId}");
		this.request.setPathInfo("/some/other/path/idp-registration-id");
		this.request.setParameter(Saml2ParameterNames.SAML_ART, "samlart");
		Assertions.assertTrue(this.filter.requiresAuthentication(this.request, this.response));
	}

	@Test
	public void attemptAuthenticationWhenSamlResponseAndRegistrationIdDoesNotExistThenThrowsException() {
		given(this.repository.findByRegistrationId("non-existent-id")).willReturn(null);
		this.filter = new Saml2WebSsoAuthenticationFilter(this.repository, "/some/other/path/{registrationId}");
		this.request.setPathInfo("/some/other/path/non-existent-id");
		this.request.setParameter(Saml2ParameterNames.SAML_RESPONSE, "response");
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.filter.attemptAuthentication(this.request, this.response))
				.withMessage("No relying party registration found");
	}

	@Test
	public void attemptAuthenticationWhenSamlArtAndRegistrationIdDoesNotExistThenThrowsException() {
		given(this.repository.findByRegistrationId("non-existent-id")).willReturn(null);
		this.filter = new Saml2WebSsoAuthenticationFilter(this.repository, "/some/other/path/{registrationId}");
		this.request.setPathInfo("/some/other/path/non-existent-id");
		this.request.setParameter(Saml2ParameterNames.SAML_ART, "art");
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.filter.attemptAuthentication(this.request, this.response))
				.withMessage("No relying party registration found");
	}
	
	@Test
	public void attemptAuthenticationWhenSamlArtThenUseArtifactAuthenticationConverter() throws AuthenticationException, IOException {
		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		AuthenticationConverter artifactAuthenticationConverter = mock(AuthenticationConverter.class);
		given(artifactAuthenticationConverter.convert(this.request)).willReturn(TestSaml2AuthenticationTokens.token());
		this.filter = new Saml2WebSsoAuthenticationFilter(authenticationConverter, artifactAuthenticationConverter, "/some/other/path/{registrationId}");
		this.filter.setAuthenticationManager((authentication) -> null);
		this.request.setPathInfo("/some/other/path/idp-registration-id");
		this.request.setParameter(Saml2ParameterNames.SAML_ART, "art");
		this.filter.attemptAuthentication(this.request, this.response);
		verifyNoInteractions(authenticationConverter);
		verify(artifactAuthenticationConverter).convert(request);
	}
	
	@Test
	public void attemptAuthenticationWhenSamlResponseThenUseAuthenticationConverter() throws AuthenticationException, IOException {
		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		AuthenticationConverter artifactAuthenticationConverter = mock(AuthenticationConverter.class);
		given(authenticationConverter.convert(this.request)).willReturn(TestSaml2AuthenticationTokens.token());
		this.filter = new Saml2WebSsoAuthenticationFilter(authenticationConverter, artifactAuthenticationConverter, "/some/other/path/{registrationId}");
		this.filter.setAuthenticationManager((authentication) -> null);
		this.request.setPathInfo("/some/other/path/idp-registration-id");
		this.request.setParameter(Saml2ParameterNames.SAML_RESPONSE, "response");
		this.filter.attemptAuthentication(this.request, this.response);
		verifyNoInteractions(artifactAuthenticationConverter);
		verify(authenticationConverter).convert(request);
	}
	
	@Test
	public void attemptAuthenticationWhenSamlArtAndSavedAuthnRequestThenRemovesAuthnRequest() throws AuthenticationException, IOException {
		Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository = mock(
				Saml2AuthenticationRequestRepository.class);
		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		AuthenticationConverter artifactAuthenticationConverter = mock(AuthenticationConverter.class);
		given(artifactAuthenticationConverter.convert(this.request)).willReturn(TestSaml2AuthenticationTokens.token());
		this.filter = new Saml2WebSsoAuthenticationFilter(authenticationConverter, artifactAuthenticationConverter, "/some/other/path/{registrationId}");
		this.filter.setAuthenticationManager((authentication) -> null);
		this.request.setPathInfo("/some/other/path/idp-registration-id");
		this.filter.setAuthenticationRequestRepository(authenticationRequestRepository);
		this.request.setParameter(Saml2ParameterNames.SAML_ART, "art");
		this.filter.attemptAuthentication(this.request, this.response);
		verify(authenticationRequestRepository).removeAuthenticationRequest(this.request, this.response);
	}
	
	@Test
	public void attemptAuthenticationWhenSamlResponseAndSavedAuthnRequestThenRemovesAuthnRequest() throws AuthenticationException, IOException {
		Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository = mock(
				Saml2AuthenticationRequestRepository.class);
		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		AuthenticationConverter artifactAuthenticationConverter = mock(AuthenticationConverter.class);
		given(authenticationConverter.convert(this.request)).willReturn(TestSaml2AuthenticationTokens.token());
		this.filter = new Saml2WebSsoAuthenticationFilter(authenticationConverter, artifactAuthenticationConverter, "/some/other/path/{registrationId}");
		this.filter.setAuthenticationManager((authentication) -> null);
		this.request.setPathInfo("/some/other/path/idp-registration-id");
		this.filter.setAuthenticationRequestRepository(authenticationRequestRepository);
		this.request.setParameter(Saml2ParameterNames.SAML_RESPONSE, "response");
		this.filter.attemptAuthentication(this.request, this.response);
		verify(authenticationRequestRepository).removeAuthenticationRequest(this.request, this.response);
	}
	
	@Test
	public void attemptAuthenticationAddsDetailsSamlResponse() throws AuthenticationException, IOException {
		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		AuthenticationConverter artifactAuthenticationConverter = mock(AuthenticationConverter.class);
		final Saml2AuthenticationToken token = TestSaml2AuthenticationTokens.token();
		given(authenticationConverter.convert(this.request)).willReturn(token);
		final AuthenticationDetailsSource authenticationDetailsSource = mock(AuthenticationDetailsSource.class);
		final WebAuthenticationDetails details = mock(WebAuthenticationDetails.class);
		given(authenticationDetailsSource.buildDetails(this.request)).willReturn(details);
		this.filter = new Saml2WebSsoAuthenticationFilter(authenticationConverter, artifactAuthenticationConverter, "/some/other/path/{registrationId}");
		this.filter.setAuthenticationManager((authentication) -> null);
		this.filter.setAuthenticationDetailsSource(authenticationDetailsSource);
		this.request.setPathInfo("/some/other/path/idp-registration-id");
		this.request.setParameter(Saml2ParameterNames.SAML_RESPONSE, "response");
		this.filter.attemptAuthentication(this.request, this.response);
		Assertions.assertEquals(details, token.getDetails());
	}
	
	@Test
	public void attemptAuthenticationAddsDetailsSamlArt() throws AuthenticationException, IOException {
		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		AuthenticationConverter artifactAuthenticationConverter = mock(AuthenticationConverter.class);
		final Saml2AuthenticationToken token = TestSaml2AuthenticationTokens.token();
		given(artifactAuthenticationConverter.convert(this.request)).willReturn(token);
		final AuthenticationDetailsSource authenticationDetailsSource = mock(AuthenticationDetailsSource.class);
		final WebAuthenticationDetails details = mock(WebAuthenticationDetails.class);
		given(authenticationDetailsSource.buildDetails(this.request)).willReturn(details);
		this.filter = new Saml2WebSsoAuthenticationFilter(authenticationConverter, artifactAuthenticationConverter, "/some/other/path/{registrationId}");
		this.filter.setAuthenticationManager((authentication) -> null);
		this.filter.setAuthenticationDetailsSource(authenticationDetailsSource);
		this.request.setPathInfo("/some/other/path/idp-registration-id");
		this.request.setParameter(Saml2ParameterNames.SAML_ART, "samlart");
		this.filter.attemptAuthentication(this.request, this.response);
		Assertions.assertEquals(details, token.getDetails());
	}
	
	@Test
	public void attemptAuthenticationWhenNoSamArtNorSamResponseThenThrowsException() {
		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		this.filter = new Saml2WebSsoAuthenticationFilter(authenticationConverter, authenticationConverter, "/some/other/path/{registrationId}");
		this.request.setPathInfo("/some/other/path/idp-registration-id");
		assertThatExceptionOfType(Saml2AuthenticationException.class)
		.isThrownBy(() -> this.filter.attemptAuthentication(this.request, this.response))
		.withMessage("No response found");
	}
	
	@Test
	public void attemptAuthenticationWhenSamlArtAndAuthenticationNotAbstractAuthenticationTokenDoesNotAddDetails() {
		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		AuthenticationConverter artifactAuthenticationConverter = mock(AuthenticationConverter.class);
		final Authentication authenticationWithoutDetails = mock(Authentication.class);
		given(artifactAuthenticationConverter.convert(this.request)).willReturn(authenticationWithoutDetails);
		final AuthenticationDetailsSource authenticationDetailsSource = mock(AuthenticationDetailsSource.class);
		this.filter = new Saml2WebSsoAuthenticationFilter(authenticationConverter, artifactAuthenticationConverter, "/some/other/path/{registrationId}");
		this.filter.setAuthenticationManager((authentication) -> null);
		this.filter.setAuthenticationDetailsSource(authenticationDetailsSource);
		this.request.setPathInfo("/some/other/path/idp-registration-id");
		this.request.setParameter(Saml2ParameterNames.SAML_ART, "art");
		assertThatNoException().isThrownBy(() -> this.filter.attemptAuthentication(this.request, this.response));
		verifyNoInteractions(authenticationDetailsSource);
	}
	
	@Test
	public void attemptAuthenticationWhenSamlResponseAndAuthenticationNotAbstractAuthenticationTokenDoesNotAddDetails() {
		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		AuthenticationConverter artifactAuthenticationConverter = mock(AuthenticationConverter.class);
		final Authentication authenticationWithoutDetails = mock(Authentication.class);
		given(authenticationConverter.convert(this.request)).willReturn(authenticationWithoutDetails);
		final AuthenticationDetailsSource authenticationDetailsSource = mock(AuthenticationDetailsSource.class);
		this.filter = new Saml2WebSsoAuthenticationFilter(authenticationConverter, artifactAuthenticationConverter, "/some/other/path/{registrationId}");
		this.filter.setAuthenticationManager((authentication) -> null);
		this.filter.setAuthenticationDetailsSource(authenticationDetailsSource);
		this.request.setPathInfo("/some/other/path/idp-registration-id");
		this.request.setParameter(Saml2ParameterNames.SAML_RESPONSE, "response");
		assertThatNoException().isThrownBy(() -> this.filter.attemptAuthentication(this.request, this.response));
		verifyNoInteractions(authenticationDetailsSource);
	}

	@Test
	public void setAuthenticationRequestRepositoryWhenNullThenThrowsIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setAuthenticationRequestRepository(null))
				.withMessage("authenticationRequestRepository cannot be null");
	}

	@Test
	public void setAuthenticationRequestRepositoryWhenExpectedAuthenticationConverterTypeThenSetLoaderIntoConverter() {
		Saml2AuthenticationTokenConverter authenticationConverter = mock(Saml2AuthenticationTokenConverter.class);
		Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository = mock(
				Saml2AuthenticationRequestRepository.class);
		this.filter = new Saml2WebSsoAuthenticationFilter(authenticationConverter, authenticationConverter, "/some/other/path/{registrationId}");
		this.filter.setAuthenticationRequestRepository(authenticationRequestRepository);
		verify(authenticationConverter).setAuthenticationRequestRepository(authenticationRequestRepository);
	}

	@Test
	public void setAuthenticationRequestRepositoryWhenNotExpectedAuthenticationConverterTypeThenDoNotSet() {
		AuthenticationConverter authenticationConverter = mock(AuthenticationConverter.class);
		Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository = mock(
				Saml2AuthenticationRequestRepository.class);
		this.filter = new Saml2WebSsoAuthenticationFilter(authenticationConverter, authenticationConverter, "/some/other/path/{registrationId}");
		this.filter.setAuthenticationRequestRepository(authenticationRequestRepository);
		verifyNoInteractions(authenticationConverter);
	}

	@Test
	public void doFilterWhenSamlResponseAndPathStartsWithRegistrationIdThenAuthenticates() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		given(this.repository.findByRegistrationId("registration-id")).willReturn(registration);
		given(this.authenticationManager.authenticate(authentication)).willReturn(authentication);
		String loginProcessingUrl = "/{registrationId}/login/saml2/sso";
		RequestMatcher matcher = new AntPathRequestMatcher(loginProcessingUrl);
		DefaultRelyingPartyRegistrationResolver delegate = new DefaultRelyingPartyRegistrationResolver(this.repository);
		RelyingPartyRegistrationResolver resolver = (request, id) -> {
			String registrationId = matcher.matcher(request).getVariables().get("registrationId");
			return delegate.resolve(request, registrationId);
		};
		Saml2AuthenticationTokenConverter authenticationConverter = new Saml2AuthenticationTokenConverter(resolver);
		Saml2ArtifactAuthenticationTokenConverter artifactAuthenticationConverter = new Saml2ArtifactAuthenticationTokenConverter(resolver);
		this.filter = new Saml2WebSsoAuthenticationFilter(authenticationConverter, artifactAuthenticationConverter, loginProcessingUrl);
		this.filter.setAuthenticationManager(this.authenticationManager);
		this.request.setPathInfo("/registration-id/login/saml2/sso");
		this.request.setParameter(Saml2ParameterNames.SAML_RESPONSE, "response");
		this.filter.doFilter(this.request, this.response, new MockFilterChain());
		verify(this.repository).findByRegistrationId("registration-id");
	}

	@Test
	public void doFilterWhenSamlArtAndPathStartsWithRegistrationIdThenAuthenticates() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		given(this.repository.findByRegistrationId("registration-id")).willReturn(registration);
		given(this.authenticationManager.authenticate(authentication)).willReturn(authentication);
		String loginProcessingUrl = "/{registrationId}/login/saml2/sso";
		RequestMatcher matcher = new AntPathRequestMatcher(loginProcessingUrl);
		DefaultRelyingPartyRegistrationResolver delegate = new DefaultRelyingPartyRegistrationResolver(this.repository);
		RelyingPartyRegistrationResolver resolver = (request, id) -> {
			String registrationId = matcher.matcher(request).getVariables().get("registrationId");
			return delegate.resolve(request, registrationId);
		};
		Saml2AuthenticationTokenConverter authenticationConverter = new Saml2AuthenticationTokenConverter(resolver);
		Saml2ArtifactAuthenticationTokenConverter artifactAuthenticationConverter = new Saml2ArtifactAuthenticationTokenConverter(resolver);
		this.filter = new Saml2WebSsoAuthenticationFilter(authenticationConverter, artifactAuthenticationConverter, loginProcessingUrl);
		this.filter.setAuthenticationManager(this.authenticationManager);
		this.request.setPathInfo("/registration-id/login/saml2/sso");
		this.request.setParameter(Saml2ParameterNames.SAML_ART, "art");
		this.filter.doFilter(this.request, this.response, new MockFilterChain());
		verify(this.repository, times(2)).findByRegistrationId("registration-id");
	}

}
