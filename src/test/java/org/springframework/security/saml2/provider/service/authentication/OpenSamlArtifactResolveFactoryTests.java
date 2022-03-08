/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.saml2.provider.service.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.joda.time.DateTime;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.credentials.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

/**
 * Tests for {@link OpenSamlArtifactResolveFactory}
 */
public class OpenSamlArtifactResolveFactoryTests {

	private OpenSamlArtifactResolveFactory factory;

	private Saml2ArtifactResolveContext.Builder contextBuilder;

	private Saml2ArtifactResolveContext context;

	private RelyingPartyRegistration.Builder relyingPartyRegistrationBuilder;

	private RelyingPartyRegistration relyingPartyRegistration;

	private final static String artifactResolutionUrl = "https://destination/artifactResolution";

	@BeforeEach
	public void setUp() {
		this.relyingPartyRegistrationBuilder = RelyingPartyRegistration.withRegistrationId("id")
				.assertionConsumerServiceLocation("template")
				.entityId("local-entity-id")
				.assertingPartyDetails((party) -> party.entityId("remote-entity-id")
						.singleSignOnServiceLocation("https://destination/sso")
						.artifactResolveServiceLocation(artifactResolutionUrl))
				.credentials((c) -> c.add(TestSaml2X509Credentials.relyingPartySigningCredential()));
		this.relyingPartyRegistration = this.relyingPartyRegistrationBuilder.build();
		this.contextBuilder = Saml2ArtifactResolveContext.builder().issuer("https://issuer")
				.relyingPartyRegistration(this.relyingPartyRegistration)
				.samlArt("samlartvalue");
		this.context = this.contextBuilder.build();
		this.factory = new OpenSamlArtifactResolveFactory();
	}

	@Test
	public void createSoapArtifactResolveWhenNotSignRequestThenNoSignatureIsPresent() {
		this.context = this.contextBuilder
				.relyingPartyRegistration(
						RelyingPartyRegistration.withRelyingPartyRegistration(this.relyingPartyRegistration)
								.providerDetails((c) -> c.signAuthNRequest(false)).build())
				.build();
		Saml2SoapArtifactResolution result = this.factory.createArtifactResolution(this.context);
		assertThat(result.getArtifactResolve()).isNotNull();
		assertThat(result.getArtifactResolveUri()).isEqualTo(artifactResolutionUrl);
		assertThat(result.getBinding()).isEqualTo(Saml2MessageBinding.SOAP);
		assertThat(OpenSamlSigningUtils.serialize(result.getArtifactResolve())).doesNotContain("ds:Signature").contains("<saml2p:Artifact>samlartvalue</saml2p:Artifact>");
	}

	@Test
	public void createSoapArtifactResolveWhenSignRequestThenSignatureIsPresent() {
		this.context = this.contextBuilder
				.relyingPartyRegistration(
						RelyingPartyRegistration.withRelyingPartyRegistration(this.relyingPartyRegistration).build())
				.build();
		Saml2SoapArtifactResolution result = this.factory.createArtifactResolution(this.context);
		assertThat(result.getArtifactResolve()).isNotNull();
		assertThat(result.getArtifactResolveUri()).isEqualTo(artifactResolutionUrl);
		assertThat(result.getBinding()).isEqualTo(Saml2MessageBinding.SOAP);
		assertThat(OpenSamlSigningUtils.serialize(result.getArtifactResolve()))
				.contains("ds:Signature").contains("<saml2p:Artifact>samlartvalue</saml2p:Artifact>");;
	}

	@Test
	public void createSoapArtifactResolveWhenSignRequestThenCredentialIsRequired() {
		Saml2X509Credential credential = org.springframework.security.saml2.core.TestSaml2X509Credentials
				.relyingPartyVerifyingCredential();
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.noCredentials()
				.assertingPartyDetails((party) -> party.verificationX509Credentials((c) -> c.add(credential))).build();
		this.context = this.contextBuilder.relyingPartyRegistration(registration)
				.build();
		assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> this.factory.createArtifactResolution(this.context));
	}

	@Test
	public void createSoapArtifactResolveWhenCreateArtifactResolveThenArtifactResolveUrlIsRequired() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full()
				.assertingPartyDetails(party -> party.artifactResolveServiceLocation(null)).build();
		this.context = this.contextBuilder.relyingPartyRegistration(registration)
				.build();
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> this.factory.createArtifactResolution(this.context));
	}

	@Test
	public void createSoapArtifactResolveWhenArtifactResolveConsumerThenUses() {
		Converter<Saml2ArtifactResolveContext, ArtifactResolve> artifactResolveContextConverter = mock(
				Converter.class);
		given(artifactResolveContextConverter.convert(this.context)).willReturn(artifactResolve());
		this.factory.setArtifactResolveContextConverter(artifactResolveContextConverter);

		this.factory.createArtifactResolution(this.context);
		verify(artifactResolveContextConverter).convert(this.context);
	}

	@Test
	public void setArtifactResolveContextConverterWhenNullThenException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.factory.setArtifactResolveContextConverter(null));
		// @formatter:on
	}

	private ArtifactResolve artifactResolve() {
		ArtifactResolve artifactResolve = TestOpenSamlObjects.artifactResolve();
		artifactResolve.setIssueInstant(DateTime.now());
		return artifactResolve;
	}

}
