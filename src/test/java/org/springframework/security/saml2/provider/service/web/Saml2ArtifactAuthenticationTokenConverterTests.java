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

package org.springframework.security.saml2.provider.service.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2ArtifactAuthenticationToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2ArtifactResolveFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.soap.SOAPClient;

@ExtendWith(MockitoExtension.class)
public class Saml2ArtifactAuthenticationTokenConverterTests {

	@Mock
	RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	RelyingPartyRegistration relyingPartyRegistration = TestRelyingPartyRegistrations.full().build();

	Saml2ArtifactAuthenticationTokenConverter converter;

	@Mock
	SOAPClient soapClient;

	@Mock
	ArtifactResponse artifactResponse;
	
	@Mock
	Saml2ArtifactResolveFactory artifactResolveFactory;

	@Mock
	Saml2ArtifactResolveContextResolver artifactResolveContextResolver;

	@BeforeEach
	public void setup() {
		this.converter = new Saml2ArtifactAuthenticationTokenConverter(this.relyingPartyRegistrationResolver);
		this.converter.setSoapClient(soapClient);
	}

	@Test
	public void convertWhenSamlResponseThenToken() {
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(this.relyingPartyRegistration);
		given(this.soapClient.send(any(XMLObject.class), any(), any()))
				.willReturn(this.artifactResponse);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter(Saml2ParameterNames.SAML_ART, "art");
		Saml2ArtifactAuthenticationToken token = converter.convert(request);
		assertThat(token.getSaml2ArtifactResponse()).isEqualTo(this.artifactResponse);
		assertThat(token.getRelyingPartyRegistration().getRegistrationId())
				.isEqualTo(this.relyingPartyRegistration.getRegistrationId());
	}

	@Test
	public void convertWhenResponseIsNotArtifactResponseThenAuthenticationException() {
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(this.relyingPartyRegistration);
		given(this.soapClient.send(any(XMLObject.class), any(), any()))
				.willReturn(mock(Response.class));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter(Saml2ParameterNames.SAML_ART, "art");
		assertThatExceptionOfType(Saml2AuthenticationException.class)
			.isThrownBy(() -> converter.convert(request))
			.withMessageContaining("SOAP message payload was not an instance of ArtifactResponse: org.opensaml.saml.saml2.core.Response");
	}
	
	@Test
	public void convertWhenNoSamlArtThenNull() {
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(this.relyingPartyRegistration);
		MockHttpServletRequest request = new MockHttpServletRequest();
		assertThat(converter.convert(request)).isNull();
	}

	@Test
	public void convertWhenNoRelyingPartyRegistrationThenNull() {
		given(this.relyingPartyRegistrationResolver.resolve(any(), any()))
				.willReturn(null);
		MockHttpServletRequest request = new MockHttpServletRequest();
		assertThat(converter.convert(request)).isNull();
	}

	@Test
	public void convertWhenNoArtifactResolveContextThenNull() {
		this.converter = new Saml2ArtifactAuthenticationTokenConverter(this.relyingPartyRegistrationResolver, this.artifactResolveFactory, this.artifactResolveContextResolver);
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(this.relyingPartyRegistration);
		MockHttpServletRequest request = new MockHttpServletRequest();
		assertThat(converter.convert(request)).isNull();
	}

	@Test
	public void convertWhenSavedAuthenticationRequestThenToken() {
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(this.relyingPartyRegistration);
		given(this.soapClient.send(any(), any(), any()))
				.willReturn(this.artifactResponse);
		Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository = mock(
				Saml2AuthenticationRequestRepository.class);
		AbstractSaml2AuthenticationRequest authenticationRequest = mock(AbstractSaml2AuthenticationRequest.class);
		converter.setAuthenticationRequestRepository(authenticationRequestRepository);
		given(authenticationRequestRepository.loadAuthenticationRequest(any(HttpServletRequest.class)))
				.willReturn(authenticationRequest);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter(Saml2ParameterNames.SAML_ART, "samlart");
		Saml2ArtifactAuthenticationToken token = converter.convert(request);
		assertThat(token.getSaml2ArtifactResponse()).isEqualTo(this.artifactResponse);
		assertThat(token.getRelyingPartyRegistration().getRegistrationId())
				.isEqualTo(this.relyingPartyRegistration.getRegistrationId());
		assertThat(token.getAuthenticationRequest()).isEqualTo(authenticationRequest);
	}

	@Test
	public void constructorWhenResolverIsNullThenIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> new Saml2ArtifactAuthenticationTokenConverter((RelyingPartyRegistrationResolver) null));
	}

	@Test
	public void setAuthenticationRequestRepositoryWhenNullThenIllegalArgument() {
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> converter.setAuthenticationRequestRepository(null));
	}
	
	@Test
	public void setSoapClienaWhenNullThenIllegalArgument() {
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> converter.setSoapClient(null));
	}
}
