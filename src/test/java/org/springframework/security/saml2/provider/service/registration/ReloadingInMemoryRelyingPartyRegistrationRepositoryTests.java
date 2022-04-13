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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collection;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.saml2.Saml2Exception;

/**
 * Tests for {@link ReloadingInMemoryRelyingPartyRegistrationRepository}
 */
public class ReloadingInMemoryRelyingPartyRegistrationRepositoryTests {
	
	private static final String VALID_UNTIL = "2020-01-01T00:00:00.000Z";

	private String metadata;
	private String recoveredMetadata;
	
	private Supplier<RelyingPartyRegistration> relyingPartyRegistrationSpl;
	
	private Supplier<RelyingPartyRegistration> recoveredRelyingPartyRegistrationSpl;
	
	private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withLocale(Locale.getDefault()).withZone(ZoneOffset.UTC);
	
	private static final String REG_ID = "registration-id";
	private static final String REG_ID_RECOVERED = "registration-id-recovered";

	@BeforeEach
	public void setup() throws Exception {
		ClassPathResource resource = new ClassPathResource("test-metadata.xml");
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream()))) {
			this.metadata = reader.lines().collect(Collectors.joining());
			relyingPartyRegistrationSpl = () -> {
				try (InputStream source = new ByteArrayInputStream(metadata.getBytes())) {
					return  RelyingPartyRegistrations
			 			.fromMetadata(source)
			 			.registrationId(REG_ID)
			 			.build();
			 	} catch (Exception e) {
			 		throw new Saml2Exception(e);
				}
			};
			recoveredRelyingPartyRegistrationSpl = () -> {
				try (InputStream source = new ByteArrayInputStream(recoveredMetadata.getBytes())) {
					return  RelyingPartyRegistrations
			 			.fromMetadata(source)
			 			.registrationId(REG_ID_RECOVERED)
			 			.build();
			 	} catch (Exception e) {
			 		throw new Saml2Exception(e);
				}
			};
		}
	}

	@Test
	public void constructingWhenIncorrectAndRecoveredMetadataThenRefreshWithNewValidUntil() throws Exception {
		String metadataValidUntil = FORMATTER.format(Instant.now().plusSeconds(2));
		String recoveredMetadataValidUntil = FORMATTER.format(Instant.now().plusSeconds(2));
		metadata = metadata.replace(VALID_UNTIL, metadataValidUntil);
		recoveredMetadata =  metadata.replace(metadataValidUntil, recoveredMetadataValidUntil);
		ReloadingInMemoryRelyingPartyRegistrationRepository repo = new ReloadingInMemoryRelyingPartyRegistrationRepository(Arrays.asList(relyingPartyRegistrationSpl, recoveredRelyingPartyRegistrationSpl), 10000, 1500);
		assertThat(repo.findByRegistrationId(REG_ID)).isNotNull();
		assertThat(FORMATTER.format(repo.findByRegistrationId(REG_ID).getValidUntil())).isEqualTo(metadataValidUntil);
		assertThat(repo.findByRegistrationId(REG_ID_RECOVERED)).isNotNull();
		assertThat(FORMATTER.format(repo.findByRegistrationId(REG_ID_RECOVERED).getValidUntil())).isEqualTo(recoveredMetadataValidUntil);
		
		String metadataNewValidUntil = FORMATTER.format(Instant.now().plus(2, ChronoUnit.HOURS));
		metadata = metadata.replace(metadataValidUntil, metadataNewValidUntil);
		recoveredMetadata = null;
        CountDownLatch cdl = new CountDownLatch(1);
        cdl.await(2, TimeUnit.SECONDS);
		assertThat(repo.findByRegistrationId(REG_ID)).isNotNull();
		assertThat(FORMATTER.format(repo.findByRegistrationId(REG_ID).getValidUntil())).isEqualTo(metadataNewValidUntil);
		assertThat(repo.findByRegistrationId(REG_ID_RECOVERED)).isNotNull();
		assertThat(FORMATTER.format(repo.findByRegistrationId(REG_ID_RECOVERED).getValidUntil())).isEqualTo(recoveredMetadataValidUntil);

		String recoveredMetadataNewValidUntil = FORMATTER.format(Instant.now().plus(3, ChronoUnit.HOURS));
		recoveredMetadata = metadata.replace(metadataNewValidUntil, recoveredMetadataNewValidUntil);
        cdl = new CountDownLatch(1);
        cdl.await(2, TimeUnit.SECONDS);
		assertThat(repo.findByRegistrationId(REG_ID)).isNotNull();
		assertThat(FORMATTER.format(repo.findByRegistrationId(REG_ID).getValidUntil())).isEqualTo(metadataNewValidUntil);
		assertThat(repo.findByRegistrationId(REG_ID_RECOVERED)).isNotNull();
		assertThat(FORMATTER.format(repo.findByRegistrationId(REG_ID_RECOVERED).getValidUntil())).isEqualTo(recoveredMetadataNewValidUntil);
		
		repo.destroy();
	}

	@Test
	public void constructingWhenIncorrectMetadataThenSamlException() throws Exception {
		metadata = null;
		Collection<Supplier<RelyingPartyRegistration>> arr = Arrays.asList(relyingPartyRegistrationSpl);
		assertThatExceptionOfType(Saml2Exception.class)
		.isThrownBy(() -> new ReloadingInMemoryRelyingPartyRegistrationRepository(arr, 10000, 1500))
		.satisfies(ex -> ex.getCause().getClass().isInstance(new NullPointerException()));
	}
}
