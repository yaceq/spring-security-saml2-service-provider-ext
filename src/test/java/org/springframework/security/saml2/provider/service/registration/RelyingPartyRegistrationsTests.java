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

package org.springframework.security.saml2.provider.service.registration;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml2.Saml2Exception;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link RelyingPartyRegistration}
 */
public class RelyingPartyRegistrationsTests {

	private String metadata;

	@BeforeEach
	public void setup() throws Exception {
		ClassPathResource resource = new ClassPathResource("test-metadata.xml");
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream()))) {
			this.metadata = reader.lines().collect(Collectors.joining());
		}
	}

	@Test
	public void fromMetadataUrlLocationWhenResolvableThenPopulatesBuilder() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.enqueue(new MockResponse().setBody(this.metadata).setResponseCode(200));
			RelyingPartyRegistration registration = RelyingPartyRegistrations
					.fromMetadataLocation(server.url("/").toString()).entityId("rp").build();
			RelyingPartyRegistration.AssertingPartyDetails details = registration.getAssertingPartyDetails();
			assertThat(details.getEntityId()).isEqualTo("https://idp.example.com/idp/shibboleth");
			assertThat(details.getSingleSignOnServiceLocation())
					.isEqualTo("https://idp.example.com/idp/profile/SAML2/POST/SSO");
			assertThat(details.getSingleSignOnServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
			assertThat(details.getArtifactResolveServiceLocation())
			.isEqualTo("https://idp.example.com/idp/profile/SAML2/POST/AR");
			assertThat(details.getArtifactResolveServiceBinding()).isEqualTo(Saml2MessageBinding.SOAP);
			assertThat(details.getSingleLogoutServiceLocation())
			.isEqualTo("https://idp.example.com/idp/profile/SAML2/POST/SLO");
			assertThat(details.getSingleLogoutServiceBinding()).isEqualTo(Saml2MessageBinding.REDIRECT);
			assertThat(details.getVerificationX509Credentials()).hasSize(1);
			assertThat(details.getEncryptionX509Credentials()).hasSize(1);
		}
	}

	@Test
	public void fromMetadataUrlLocationWhenUnresolvableThenSaml2Exception() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.enqueue(new MockResponse().setBody(this.metadata).setResponseCode(200));
			String url = server.url("/").toString();
			server.shutdown();
			assertThatExceptionOfType(Saml2Exception.class)
					.isThrownBy(() -> RelyingPartyRegistrations.fromMetadataLocation(url));
		}
	}

	@Test
	public void fromMetadataUrlLocationWhenMalformedResponseThenSaml2Exception() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.enqueue(new MockResponse().setBody("malformed").setResponseCode(200));
			String url = server.url("/").toString();
			assertThatExceptionOfType(Saml2Exception.class)
					.isThrownBy(() -> RelyingPartyRegistrations.fromMetadataLocation(url));
		}
	}

	@Test
	public void fromMetadataFileLocationWhenResolvableThenPopulatesBuilder() {
		File file = new File("src/test/resources/test-metadata.xml");
		RelyingPartyRegistration registration = RelyingPartyRegistrations
				.fromMetadataLocation("file:" + file.getAbsolutePath()).entityId("rp").build();
		RelyingPartyRegistration.AssertingPartyDetails details = registration.getAssertingPartyDetails();
		assertThat(details.getEntityId()).isEqualTo("https://idp.example.com/idp/shibboleth");
		assertThat(details.getSingleSignOnServiceLocation())
				.isEqualTo("https://idp.example.com/idp/profile/SAML2/POST/SSO");
		assertThat(details.getSingleSignOnServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
		assertThat(details.getVerificationX509Credentials()).hasSize(1);
		assertThat(details.getEncryptionX509Credentials()).hasSize(1);
	}

	@Test
	public void fromMetadataFileLocationWhenNotFoundThenSaml2Exception() {
		assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> RelyingPartyRegistrations.fromMetadataLocation("filePath"));
	}

	@Test
	public void fromMetadataInputStreamWhenResolvableThenPopulatesBuilder() throws Exception {
		try (InputStream source = new ByteArrayInputStream(this.metadata.getBytes())) {
			RelyingPartyRegistration registration = RelyingPartyRegistrations.fromMetadata(source).entityId("rp")
					.build();
			RelyingPartyRegistration.AssertingPartyDetails details = registration.getAssertingPartyDetails();
			assertThat(details.getEntityId()).isEqualTo("https://idp.example.com/idp/shibboleth");
			assertThat(details.getSingleSignOnServiceLocation())
					.isEqualTo("https://idp.example.com/idp/profile/SAML2/POST/SSO");
			assertThat(details.getSingleSignOnServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
			assertThat(details.getVerificationX509Credentials()).hasSize(1);
			assertThat(details.getEncryptionX509Credentials()).hasSize(1);
		}
	}

	@Test
	public void fromMetadataInputStreamWhenEmptyThenSaml2Exception() throws Exception {
		try (InputStream source = new ByteArrayInputStream("".getBytes())) {
			assertThatExceptionOfType(Saml2Exception.class)
					.isThrownBy(() -> RelyingPartyRegistrations.fromMetadata(source));
		}
	}

}
