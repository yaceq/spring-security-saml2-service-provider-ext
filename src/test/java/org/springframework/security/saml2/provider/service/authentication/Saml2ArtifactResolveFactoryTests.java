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

import org.junit.jupiter.api.Test;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

/**
 * Tests for {@link Saml2ArtifactResolveFactory} default interface methods
 */
public class Saml2ArtifactResolveFactoryTests {

	
	@Test
	public void createSoapArtifactResolution() {
		Saml2SoapArtifactResolution resolution = new Saml2SoapArtifactResolution("uri", TestOpenSamlObjects.artifactResolve());
		Saml2ArtifactResolveFactory factory = (request) -> resolution;
		Saml2ArtifactResolveContext request = Saml2ArtifactResolveContext.builder()
				.relyingPartyRegistration(TestRelyingPartyRegistrations.full().build()).issuer("https://example.com/issuer")
				.samlArt("samlartvalue").build();
		Saml2SoapArtifactResolution response = factory.createArtifactResolution(request);
		assertThat(response).isEqualToComparingFieldByField(resolution);
	}

}
