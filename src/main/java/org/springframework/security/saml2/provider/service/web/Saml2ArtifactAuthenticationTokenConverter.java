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

import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.core.Version;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlArtifactResolveFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2ArtifactAuthenticationToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2ArtifactResolveContext;
import org.springframework.security.saml2.provider.service.authentication.Saml2ArtifactResolveFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2SoapArtifactResolution;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.soap.HttpSOAPClient;
import org.springframework.security.saml2.soap.SOAPClient;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationConverter} that generates a
 * {@link Saml2ArtifactAuthenticationToken} appropriate for authenticated a SAML
 * 2.0 Assertion against an
 * {@link org.springframework.security.authentication.AuthenticationManager}.
 *
 * @author Josh Cummings
 * @since 5.4
 */
public final class Saml2ArtifactAuthenticationTokenConverter implements AuthenticationConverter {

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	private Function<HttpServletRequest, AbstractSaml2AuthenticationRequest> loader;

	private final Saml2ArtifactResolveFactory artifactResolveFactory;

	private final Saml2ArtifactResolveContextResolver artifactResolveContextResolver;
	
    private SOAPClient soapClient = new HttpSOAPClient();

	/**
	 * Constructs a {@link Saml2ArtifactAuthenticationTokenConverter} given a
	 * strategy for resolving {@link RelyingPartyRegistration}s
	 * 
	 * @param relyingPartyRegistrationResolver the strategy for resolving
	 *                                         {@link RelyingPartyRegistration}s
	 */
	public Saml2ArtifactAuthenticationTokenConverter(
			RelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
			Saml2ArtifactResolveFactory artifactResolveFactory,
			Saml2ArtifactResolveContextResolver artifactResolveContextResolver) {
		Assert.notNull(relyingPartyRegistrationResolver, "relyingPartyRegistrationResolver cannot be null");
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
		this.loader = new HttpSessionSaml2AuthenticationRequestRepository()::loadAuthenticationRequest;
		
		this.artifactResolveFactory = artifactResolveFactory;
		this.artifactResolveContextResolver = artifactResolveContextResolver;
	}
	
	public Saml2ArtifactAuthenticationTokenConverter(
			RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		this(relyingPartyRegistrationResolver, getArtifactResolveFactory(), getArtifactResolveContextResolver(relyingPartyRegistrationResolver));
	}

	private static Saml2ArtifactResolveFactory getArtifactResolveFactory() {
		if (Version.getVersion().startsWith("4")) {
			return null; //new OpenSaml4ArtifactResolveFactory(); //TODO
		}
		return new OpenSamlArtifactResolveFactory();
	}

	private static Saml2ArtifactResolveContextResolver getArtifactResolveContextResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		return new DefaultSaml2ArtifactResolveContextResolver(relyingPartyRegistrationResolver);
	}

	@Override
	public Saml2ArtifactAuthenticationToken convert(HttpServletRequest request) {
		RelyingPartyRegistration relyingPartyRegistration = this.relyingPartyRegistrationResolver.resolve(request, null);
		if (relyingPartyRegistration == null) {
			return null;
		}
		String saml2Artifact = request.getParameter(Saml2ParameterNames.SAML_ART);
		if (saml2Artifact == null) {
			return null;
		}
		Saml2ArtifactResolveContext context = this.artifactResolveContextResolver.resolve(request);
		if (context == null) {
			return null;
		}
		Saml2SoapArtifactResolution artResolve = this.artifactResolveFactory.createArtifactResolution(context);
		
		XMLObject response = soapClient.send(artResolve.getArtifactResolve(), artResolve.getArtifactResolveUri(), null);

        if (!(response instanceof ArtifactResponse)) {
			Saml2Error saml2Error = new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE,
					"SOAP message payload was not an instance of ArtifactResponse: " + response.getClass().getName());
			throw new Saml2AuthenticationException(saml2Error);
        }

		AbstractSaml2AuthenticationRequest authenticationRequest = loadAuthenticationRequest(request);
		return new Saml2ArtifactAuthenticationToken(relyingPartyRegistration, (ArtifactResponse) response,
				authenticationRequest);
	}

	
	/**
	 * Use the given {@link Saml2AuthenticationRequestRepository} to load
	 * authentication request.
	 * 
	 * @param authenticationRequestRepository the
	 *                                        {@link Saml2AuthenticationRequestRepository}
	 *                                        to use
	 * @since 5.6
	 */
	public void setAuthenticationRequestRepository(
			Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository) {
		Assert.notNull(authenticationRequestRepository, "authenticationRequestRepository cannot be null");
		this.loader = authenticationRequestRepository::loadAuthenticationRequest;
	}

	private AbstractSaml2AuthenticationRequest loadAuthenticationRequest(HttpServletRequest request) {
		return this.loader.apply(request);
	}

	public void setSoapClient(SOAPClient soapClient) {
		Assert.notNull(soapClient, "soapClient cannot be null");
		this.soapClient = soapClient;
	}
}
