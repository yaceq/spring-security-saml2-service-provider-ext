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

package org.springframework.security.saml2.provider.service.authentication;

import java.util.Collections;
import java.util.List;

import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.Assert;

/**
 * Represents an incoming SAML 2.0 response containing an assertion that has not been
 * validated. {@link Saml2ArtifactAuthenticationToken#isAuthenticated()} will always return false.
 *
 * @author Filip Hanik
 * @author Josh Cummings
 * @since 5.2
 */
public class Saml2ArtifactAuthenticationToken extends AbstractAuthenticationToken {

	private final RelyingPartyRegistration relyingPartyRegistration;

	private final ArtifactResponse saml2ArtifactResponse;
	
	private final AbstractSaml2AuthenticationRequest authenticationRequest;

	/**
	 * Creates a {@link Saml2ArtifactAuthenticationToken} with the provided parameters.
	 *
	 * Note that the given {@link RelyingPartyRegistration} should have all its templates
	 * resolved at this point. See
	 * {@link org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter}
	 * for an example of performing that resolution.
	 * @param relyingPartyRegistration the resolved {@link RelyingPartyRegistration} to
	 * use
	 * @param saml2Response the SAML 2.0 response to authenticate
	 * @param authenticationRequest the {@code AuthNRequest} sent to the asserting party
	 *
	 * @since 5.6
	 */
	public Saml2ArtifactAuthenticationToken(RelyingPartyRegistration relyingPartyRegistration, ArtifactResponse saml2ArtifactResponse,
			AbstractSaml2AuthenticationRequest authenticationRequest) {
		super(Collections.emptyList());
		Assert.notNull(relyingPartyRegistration, "relyingPartyRegistration cannot be null");
		Assert.notNull(saml2ArtifactResponse, "saml2ArtifactResponse cannot be null");
		Assert.notNull(saml2ArtifactResponse, "saml2ArtifactResponse cannot be null");
		this.relyingPartyRegistration = relyingPartyRegistration;
		this.saml2ArtifactResponse = saml2ArtifactResponse;
		this.authenticationRequest = authenticationRequest;
	}

	/**
	 * Creates a {@link Saml2ArtifactAuthenticationToken} with the provided parameters
	 *
	 * Note that the given {@link RelyingPartyRegistration} should have all its templates
	 * resolved at this point. See
	 * {@link org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter}
	 * for an example of performing that resolution.
	 * @param relyingPartyRegistration the resolved {@link RelyingPartyRegistration} to
	 * use
	 * @param saml2Response the SAML 2.0 response to authenticate
	 *
	 * @since 5.4
	 */
	public Saml2ArtifactAuthenticationToken(RelyingPartyRegistration relyingPartyRegistration, ArtifactResponse saml2ArtifactResponse) {
		this(relyingPartyRegistration, saml2ArtifactResponse, null);
	}

	/**
	 * Returns the decoded and inflated SAML 2.0 Response XML object as a string
	 * @return decoded and inflated XML data as a {@link String}
	 */
	@Override
	public Object getCredentials() {
		return null;
	}

	/**
	 * Always returns null.
	 * @return null
	 */
	@Override
	public Object getPrincipal() {
		return null;
	}

	/**
	 * Get the resolved {@link RelyingPartyRegistration} associated with the request
	 * @return the resolved {@link RelyingPartyRegistration}
	 * @since 5.4
	 */
	public RelyingPartyRegistration getRelyingPartyRegistration() {
		return this.relyingPartyRegistration;
	}

	/**
	 * Returns inflated and decoded XML representation of the SAML 2 Response
	 * @return inflated and decoded XML representation of the SAML 2 Response
	 */
	public ArtifactResponse getSaml2ArtifactResponse() {
		return this.saml2ArtifactResponse;
	}

	/**
	 * Returns the URI that the SAML 2 Response object came in on
	 * @return URI as a string
	 * @deprecated Use
	 * {@code getRelyingPartyRegistration().getAssertionConsumerServiceLocation()} instead
	 */
	@Deprecated
	public String getRecipientUri() {
		return this.relyingPartyRegistration.getAssertionConsumerServiceLocation();
	}

	/**
	 * Returns the configured entity ID of the receiving relying party, SP
	 * @return an entityID for the configured local relying party
	 * @deprecated Use {@code getRelyingPartyRegistration().getEntityId()} instead
	 */
	@Deprecated
	public String getLocalSpEntityId() {
		return this.relyingPartyRegistration.getEntityId();
	}

	/**
	 * Returns all the credentials associated with the relying party configuraiton
	 * @return all associated credentials
	 * @deprecated Get the credentials through {@link #getRelyingPartyRegistration()}
	 * instead
	 */
	@Deprecated
	public List<Saml2X509Credential> getX509Credentials() {
		return this.relyingPartyRegistration.getCredentials();
	}

	/**
	 * @return false
	 */
	@Override
	public boolean isAuthenticated() {
		return false;
	}

	/**
	 * The state of this object cannot be changed. Will always throw an exception
	 * @param authenticated ignored
	 */
	@Override
	public void setAuthenticated(boolean authenticated) {
		throw new IllegalArgumentException();
	}

	/**
	 * Returns the configured IDP, asserting party, entity ID
	 * @return a string representing the entity ID
	 * @deprecated Use
	 * {@code getRelyingPartyRegistration().getAssertingPartyDetails().getEntityId()}
	 * instead
	 */
	@Deprecated
	public String getIdpEntityId() {
		return this.relyingPartyRegistration.getAssertingPartyDetails().getEntityId();
	}

	/**
	 * Returns the authentication request sent to the assertion party or {@code null} if
	 * no authentication request is present
	 * @return the authentication request sent to the assertion party
	 * @since 5.6
	 */
	public AbstractSaml2AuthenticationRequest getAuthenticationRequest() {
		return this.authenticationRequest;
	}

}
