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

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.Assert;


public class Saml2ArtifactResolveContext {

	private final RelyingPartyRegistration relyingPartyRegistration;

	private final String issuer;
	
	private final String samlArt;

	protected Saml2ArtifactResolveContext(RelyingPartyRegistration relyingPartyRegistration, String issuer, String samlArt) {
		Assert.hasText(issuer, "issuer cannot be null or empty");
		Assert.notNull(relyingPartyRegistration, "relyingPartyRegistration cannot be null");
		Assert.hasText(samlArt, "samlArt cannot be null or empty");
		this.issuer = issuer;
		this.relyingPartyRegistration = relyingPartyRegistration;
		this.samlArt = samlArt;
	}

	/**
	 * Returns the {@link RelyingPartyRegistration} configuration for which the
	 * AuthNRequest is intended for.
	 * @return the {@link RelyingPartyRegistration} configuration
	 */
	public RelyingPartyRegistration getRelyingPartyRegistration() {
		return this.relyingPartyRegistration;
	}

	/**
	 * Returns the {@code Issuer} value to be used in the {@code AuthNRequest} object.
	 * This property should be used to populate the {@code AuthNRequest.Issuer} XML
	 * element. This value typically is a URI, but can be an arbitrary string.
	 * @return the Issuer value
	 */
	public String getIssuer() {
		return this.issuer;
	}

	/**
	 * Returns the SamlArt value, if present in the parameters
	 * @return the SamlArt value, or null if not available
	 */
	public String getSamlArt() {
		return this.samlArt;
	}

	/**
	 * Returns the {@code Destination}, the WEB Single Sign On URI, for this
	 * authentication request. This property can also populate the
	 * {@code AuthNRequest.Destination} XML attribute.
	 * @return the Destination value
	 */
	public String getDestination() {
		return this.getRelyingPartyRegistration().getAssertingPartyDetails().getArtifactResolveServiceLocation();
	}

	/**
	 * A builder for {@link Saml2ArtifactResolveContext}.
	 * @return a builder object
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A builder for {@link Saml2ArtifactResolveContext}.
	 */
	public static final class Builder {

		private String issuer;
		
		private RelyingPartyRegistration relyingPartyRegistration;
		
		private String samlArt;

		private Builder() {
		}

		/**
		 * Sets the issuer for the authentication request.
		 * @param issuer - a required value
		 * @return this {@code Builder}
		 */
		public Builder issuer(String issuer) {
			this.issuer = issuer;
			return this;
		}

		/**
		 * Sets the {@link RelyingPartyRegistration} used to build the authentication
		 * request.
		 * @param relyingPartyRegistration - a required value
		 * @return this {@code Builder}
		 */
		public Builder relyingPartyRegistration(RelyingPartyRegistration relyingPartyRegistration) {
			this.relyingPartyRegistration = relyingPartyRegistration;
			return this;
		}
		
		public Builder samlArt(String samlArt) {
			this.samlArt = samlArt;
			return this;
		}

		/**
		 * Creates a {@link Saml2ArtifactResolveContext} object.
		 * @return the Saml2AuthenticationRequest object
		 * @throws IllegalArgumentException if a required property is not set
		 */
		public Saml2ArtifactResolveContext build() {
			return new Saml2ArtifactResolveContext(this.relyingPartyRegistration, this.issuer, this.samlArt);
		}

	}

}
