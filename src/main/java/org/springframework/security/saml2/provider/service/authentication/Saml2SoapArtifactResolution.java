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

import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

public class Saml2SoapArtifactResolution extends AbstractSaml2ArtifactResolve {

	Saml2SoapArtifactResolution(String artifactResolveUri, ArtifactResolve artifactResolve) {
		super(artifactResolveUri, artifactResolve);
	}

	/**
	 * @return {@link Saml2MessageBinding#SOAP}
	 */
	@Override
	public Saml2MessageBinding getBinding() {
		return Saml2MessageBinding.SOAP;
	}

	public static Builder withArtifactResolveContext(Saml2ArtifactResolveContext context) {
		return new Builder().artifactResolveUri(context.getDestination());
	}

	/**
	 * Builder class for a {@link Saml2SoapArtifactResolution} object.
	 */
	public static final class Builder extends AbstractSaml2ArtifactResolve.Builder<Builder> {

		private Builder() {
		}

		/**
		 * Constructs an immutable {@link Saml2SoapArtifactResolution} object.
		 * @return an immutable {@link Saml2SoapArtifactResolution} object.
		 */
		public Saml2SoapArtifactResolution build() {
			return new Saml2SoapArtifactResolution(this.artifactResolveUri, this.artifactResolve);
		}

	}

}
