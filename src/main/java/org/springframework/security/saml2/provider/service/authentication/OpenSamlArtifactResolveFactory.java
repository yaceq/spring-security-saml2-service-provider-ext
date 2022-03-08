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

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

import org.joda.time.DateTime;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.saml2.core.Artifact;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.impl.ArtifactBuilder;
import org.opensaml.saml.saml2.core.impl.ArtifactResolveBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.Assert;

public final class OpenSamlArtifactResolveFactory implements Saml2ArtifactResolveFactory {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final ArtifactResolveBuilder artifactResolveBuilder;

	private final IssuerBuilder issuerBuilder;
	
	private final ArtifactBuilder artifactBuilder;

	private Clock clock = Clock.systemUTC();

	private Converter<Saml2ArtifactResolveContext, ArtifactResolve> artifactResolveContextConverter;

	/**
	 * Creates an {@link OpenSamlArtifactResolveFactory}
	 */
	public OpenSamlArtifactResolveFactory() {
		this.artifactResolveContextConverter = this::createArtifactResolve;
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.artifactResolveBuilder = (ArtifactResolveBuilder) registry.getBuilderFactory()
				.getBuilder(ArtifactResolve.DEFAULT_ELEMENT_NAME);
		this.issuerBuilder = (IssuerBuilder) registry.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		this.artifactBuilder = (ArtifactBuilder) registry.getBuilderFactory().getBuilder(Artifact.DEFAULT_ELEMENT_NAME);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2SoapArtifactResolution createArtifactResolution(Saml2ArtifactResolveContext context) {
		ArtifactResolve artifactResolve = this.artifactResolveContextConverter.convert(context);
		RelyingPartyRegistration registration = context.getRelyingPartyRegistration();
		if (registration.getAssertingPartyDetails().getWantAuthnRequestsSigned()) {
			OpenSamlSigningUtils.sign(artifactResolve, registration);
		}
		return Saml2SoapArtifactResolution.withArtifactResolveContext(context)
				.artifactResolve(artifactResolve).build();
	}


	private ArtifactResolve createArtifactResolve(Saml2ArtifactResolveContext context) {
		String issuer = context.getIssuer();
		String destination = context.getDestination();
		ArtifactResolve artRes = this.artifactResolveBuilder.buildObject();
		if (artRes.getID() == null) {
			artRes.setID("ARS" + UUID.randomUUID().toString().substring(1));
		}
		if (artRes.getIssueInstant() == null) {
			artRes.setIssueInstant(new DateTime(this.clock.millis()));
		}
		Issuer iss = this.issuerBuilder.buildObject();
		iss.setValue(issuer);
		artRes.setIssuer(iss);
		
		Artifact artifact = this.artifactBuilder.buildObject();
		artifact.setArtifact(context.getSamlArt());
		artRes.setArtifact(artifact);

		artRes.setDestination(destination);
		
		return artRes;
	}

	/**
	 * Set the strategy for building an {@link AuthnRequest} from a given context
	 * @param authenticationRequestContextConverter the conversion strategy to use
	 */
	public void setArtifactResolveContextConverter(
			Converter<Saml2ArtifactResolveContext, ArtifactResolve> artifactResolveContextConverter) {
		Assert.notNull(artifactResolveContextConverter, "artifactResolveContextConverter cannot be null");
		this.artifactResolveContextConverter = artifactResolveContextConverter;
	}

	/**
	 * Use this {@link Clock} with {@link Instant#now()} for generating timestamps
	 * @param clock the {@link Clock} to use
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

}
