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
import org.springframework.util.Assert;


public abstract class AbstractSaml2ArtifactResolve {

	private final ArtifactResolve artifactResolve;

	private final String artifactResolveUri;

	AbstractSaml2ArtifactResolve(String artifactResolveUri, ArtifactResolve artifactResolve) {
		Assert.notNull(artifactResolve, "artifactResolve cannot be null or empty");
		Assert.hasText(artifactResolveUri, "artifactResolveRequestUri cannot be null or empty");
		this.artifactResolveUri = artifactResolveUri;
		this.artifactResolve = artifactResolve;
	}


	/**
	 * Returns the URI endpoint that this AuthNRequest should be sent to.
	 * @return the URI endpoint for this message
	 */
	public String getArtifactResolveUri() {
		return this.artifactResolveUri;
	}

	public ArtifactResolve getArtifactResolve() {
		return artifactResolve;
	}

	/**
	 * Returns the binding this AuthNRequest will be sent and encoded with. If
	 * {@link Saml2MessageBinding#REDIRECT} is used, the DEFLATE encoding will be
	 * automatically applied.
	 * @return the binding this message will be sent with.
	 */
	public abstract Saml2MessageBinding getBinding();

	/**
	 * A builder for {@link AbstractSaml2ArtifactResolve} and its subclasses.
	 */
	public static class Builder<T extends Builder<T>> {

		String artifactResolveUri;
		
		ArtifactResolve artifactResolve;
		
		protected Builder() {
		}

		/**
		 * Casting the return as the generic subtype, when returning itself
		 * @return this object
		 */
		@SuppressWarnings("unchecked")
		protected final T _this() {
			return (T) this;
		}

		/**
		 * Sets the {@code authenticationRequestUri}, a URL that will receive the
		 * AuthNRequest message
		 * @param authenticationRequestUri the relay state value, unencoded.
		 * @return this object
		 */
		public T artifactResolveUri(String artifactResolveUri) {
			this.artifactResolveUri = artifactResolveUri;
			return _this();
		}

		public T artifactResolve(ArtifactResolve artifactResolve) {
			this.artifactResolve = artifactResolve;
			return _this();
		}
		
	}

}
