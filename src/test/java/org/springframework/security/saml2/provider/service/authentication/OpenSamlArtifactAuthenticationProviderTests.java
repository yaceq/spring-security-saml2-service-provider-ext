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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import javax.xml.namespace.QName;

import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.impl.XSDateTimeBuilder;
import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedAttribute;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.OneTimeUse;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.core.impl.EncryptedAssertionBuilder;
import org.opensaml.saml.saml2.core.impl.EncryptedIDBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.xmlsec.encryption.impl.EncryptedDataBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlArtifactAuthenticationProvider.ResponseToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;

/**
 * Tests for {@link OpenSamlArtifactAuthenticationProvider}
 *
 * @author Filip Hanik
 * @author Josh Cummings
 */
public class OpenSamlArtifactAuthenticationProviderTests {

	private static String DESTINATION = "https://localhost/login/saml2/sso/idp-alias";

	private static String RELYING_PARTY_ENTITY_ID = "https://localhost/saml2/service-provider-metadata/idp-alias";

	private static String ASSERTING_PARTY_ENTITY_ID = "https://some.idp.test/saml2/idp";

	private OpenSamlArtifactAuthenticationProvider provider = new OpenSamlArtifactAuthenticationProvider();

	@Test
	public void supportsWhenSaml2ArtifactAuthenticationTokenThenReturnTrue() {
		assertThat(this.provider.supports(Saml2ArtifactAuthenticationToken.class))
				.withFailMessage(
						OpenSamlArtifactAuthenticationProvider.class + "should support " + Saml2ArtifactAuthenticationToken.class)
				.isTrue();
	}

	@Test
	public void supportsWhenNotSaml2ArtifactAuthenticationTokenThenReturnFalse() {
		assertThat(!this.provider.supports(Authentication.class))
				.withFailMessage(OpenSamlArtifactAuthenticationProvider.class + "should not support " + Authentication.class)
				.isTrue();
	}

	@Test
	public void authenticateWhenInvalidDestinationInResponseThenThrowAuthenticationException() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		response.setDestination(DESTINATION + "invalid");
		response.getAssertions().add(assertion());
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.INVALID_DESTINATION));
	}

	@Test
	public void authenticateWhenInvalidDestinationInArtifactResponseThenThrowAuthenticationException() {
		ArtifactResponse artifactResponse = artifactResponse(DESTINATION + "invalid", ASSERTING_PARTY_ENTITY_ID);
		Response response = ((Response) artifactResponse.getMessage());
		response.getAssertions().add(assertion());
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.INVALID_DESTINATION));
	}
	
	@Test
	public void authenticateWhenInvalidIssuerInResponseThenThrowAuthenticationException() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		response.getIssuer().setValue(ASSERTING_PARTY_ENTITY_ID + "invalid");
		response.getAssertions().add(assertion());
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.INVALID_ISSUER));
	}

	@Test
	public void authenticateWhenInvalidIssuerInArtifactResponseThenThrowAuthenticationException() {
		ArtifactResponse artifactResponse = artifactResponse(DESTINATION, ASSERTING_PARTY_ENTITY_ID + "invalid");
		Response response = ((Response) artifactResponse.getMessage());
		response.getAssertions().add(assertion());
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.INVALID_SIGNATURE));
	}
	
	@Test
	public void authenticateWhenNoAssertionsPresentThenThrowAuthenticationException() {
		ArtifactResponse artifactResponse = artifactResponse();
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, "No assertions found in response."));
	}

	@Test
	public void authenticateWhenInvalidSignatureOnAssertionThenThrowAuthenticationException() {
		ArtifactResponse artifactResponse = artifactResponse();
		((Response) artifactResponse.getMessage()).getAssertions().add(assertion());
		Saml2ArtifactAuthenticationToken token = token(artifactResponse, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.INVALID_SIGNATURE));
	}

	@Test
	public void authenticateWhenOpenSAMLValidationErrorThenThrowAuthenticationException() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = assertion();
		assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData()
				.setNotOnOrAfter(DateTime.now().minus(Duration.standardDays(3)));
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.INVALID_ASSERTION));
	}

	@Test
	public void authenticateWhenMissingSubjectThenThrowAuthenticationException() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = assertion();
		assertion.setSubject(null);
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.SUBJECT_NOT_FOUND));
	}

	@Test
	public void authenticateWhenUsernameMissingThenThrowAuthenticationException() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = assertion();
		assertion.getSubject().getNameID().setValue(null);
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.SUBJECT_NOT_FOUND));
	}

	@Test
	public void authenticateWhenAssertionContainsValidationAddressThenItSucceeds() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = assertion();
		assertion.getSubject().getSubjectConfirmations()
		.forEach((sc) -> sc.getSubjectConfirmationData().setAddress("10.10.10.10"));
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		this.provider.authenticate(token);
	}
	
	@Test
	public void authenticateWhenAssertionContainsAttributesThenItSucceeds() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = assertion();
		List<AttributeStatement> attributes = attributeStatements();
		assertion.getAttributeStatements().addAll(attributes);
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		Authentication authentication = this.provider.authenticate(token);
		Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
		Map<String, Object> expected = new LinkedHashMap<>();
		expected.put("email", Arrays.asList("john.doe@example.com", "doe.john@example.com"));
		expected.put("name", Collections.singletonList("John Doe"));
		expected.put("age", Collections.singletonList(21));
		expected.put("website", Collections.singletonList("https://johndoe.com/"));
		expected.put("registered", Collections.singletonList(true));
		Instant registeredDate = Instant.ofEpochMilli(DateTime.parse("1970-01-01T00:00:00Z").getMillis());
		expected.put("registeredDate", Collections.singletonList(registeredDate));
		assertThat((String) principal.getFirstAttribute("name")).isEqualTo("John Doe");
		assertThat(principal.getAttributes()).isEqualTo(expected);
	}

	@Test
	public void authenticateWhenEncryptedAssertionWithoutSignatureThenItFails() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion(),
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);

		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, decrypting(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.INVALID_SIGNATURE));
	}

	@Test
	public void authenticateWhenEncryptedAssertionWithSignatureThenItSucceeds() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = TestOpenSamlObjects.signed(assertion(),
				TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion,
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, decrypting(verifying(registration())));
		this.provider.authenticate(token);
	}
	
	@Test
	public void authenticateWhenResponseWithoutSignatureThenItSucceeds() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = TestOpenSamlObjects.signed(assertion(),
				TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		TestOpenSamlObjects.signed(artifactResponse, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		Saml2ArtifactAuthenticationToken token = token(artifactResponse, decrypting(verifying(registration())));
		this.provider.authenticate(token);
	}
	
	@Test
	public void authenticateWhenEncryptedAssertionWithSignatureButResponseWithoutSignatureThenThrowAuthenticationException() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = TestOpenSamlObjects.signed(assertion(),
				TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion,
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		TestOpenSamlObjects.signed(artifactResponse, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		Saml2ArtifactAuthenticationToken token = token(artifactResponse, decrypting(verifying(registration())));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
		.isThrownBy(() -> this.provider.authenticate(token))
		.satisfies(errorOf(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA));
	}
	
	@Test
	public void authenticateWhenEncryptedAssertionWithResponseSignatureThenItSucceeds() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion(),
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, decrypting(verifying(registration())));
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenEncryptedNameIdWithSignatureThenItSucceeds() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = assertion();
		NameID nameId = assertion.getSubject().getNameID();
		EncryptedID encryptedID = TestOpenSamlObjects.encrypted(nameId,
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		assertion.getSubject().setNameID(null);
		assertion.getSubject().setEncryptedID(encryptedID);
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, decrypting(verifying(registration())));
		this.provider.authenticate(token);
	}

	@Test
	public void authenticateWhenEncryptedAttributeThenDecrypts() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = assertion();
		EncryptedAttribute attribute = TestOpenSamlObjects.encrypted("name", "value",
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		AttributeStatement statement = build(AttributeStatement.DEFAULT_ELEMENT_NAME);
		statement.getEncryptedAttributes().add(attribute);
		assertion.getAttributeStatements().add(statement);
		response.getAssertions().add(assertion);
		response.getAssertions().add(assertion);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, decrypting(verifying(registration())));
		Saml2Authentication authentication = (Saml2Authentication) this.provider.authenticate(token);
		Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
		assertThat(principal.getAttribute("name")).containsExactly("value");
	}

	@Test
	public void authenticateWhenDecryptionKeysAreMissingThenThrowAuthenticationException() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion(),
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.DECRYPTION_ERROR, "Failed to decrypt EncryptedData"));
	}

	@Test
	public void authenticateWhenDecryptionKeysAreWrongThenThrowAuthenticationException() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion(),
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()
				.decryptionX509Credentials((c) -> c.add(TestSaml2X509Credentials.assertingPartyPrivateCredential()))));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.DECRYPTION_ERROR, "Failed to decrypt EncryptedData"));
	}

	@Test
	public void writeObjectWhenTypeIsSaml2AuthenticationThenNoException() throws IOException {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = TestOpenSamlObjects.signed(assertion(),
				TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
		EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion,
				TestSaml2X509Credentials.assertingPartyEncryptingCredential());
		response.getEncryptedAssertions().add(encryptedAssertion);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, decrypting(verifying(registration())));
		Saml2Authentication authentication = (Saml2Authentication) this.provider.authenticate(token);
		// the following code will throw an exception if authentication isn't serializable
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream(1024);
		ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteStream);
		objectOutputStream.writeObject(authentication);
		objectOutputStream.flush();
	}

	@Test
	public void createDefaultAssertionValidatorWhenAssertionThenValidates() {
		Response response = TestOpenSamlObjects.signedResponseWithOneAssertion();
		Assertion assertion = response.getAssertions().get(0);
		OpenSamlArtifactAuthenticationProvider.AssertionToken assertionToken = new OpenSamlArtifactAuthenticationProvider.AssertionToken(
				assertion, token());
		assertThat(OpenSamlArtifactAuthenticationProvider.createDefaultAssertionValidator().convert(assertionToken).hasErrors())
				.isFalse();
	}

	@Test
	public void authenticateWhenDelegatingToDefaultAssertionValidatorThenUses() {
		OpenSamlArtifactAuthenticationProvider provider = new OpenSamlArtifactAuthenticationProvider();
		// @formatter:off
		provider.setAssertionValidator((assertionToken) -> OpenSamlArtifactAuthenticationProvider
				.createDefaultAssertionValidator((token) -> new ValidationContext())
				.convert(assertionToken)
				.concat(new Saml2Error("wrong error", "wrong error"))
		);
		// @formatter:on
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = assertion();
		OneTimeUse oneTimeUse = build(OneTimeUse.DEFAULT_ELEMENT_NAME);
		assertion.getConditions().getConditions().add(oneTimeUse);
		response.getAssertions().add(assertion);
		TestOpenSamlObjects.signed(response, TestSaml2X509Credentials.assertingPartySigningCredential(),
				ASSERTING_PARTY_ENTITY_ID);
		TestOpenSamlObjects.signed(artifactResponse, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		// @formatter:off
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> provider.authenticate(token)).isInstanceOf(Saml2AuthenticationException.class)
				.satisfies((error) -> assertThat(error.getSaml2Error().getErrorCode()).isEqualTo(Saml2ErrorCodes.INVALID_ASSERTION));
		// @formatter:on
	}

	@Test
	public void authenticateWhenCustomAssertionValidatorThenUses() {
		Converter<OpenSamlArtifactAuthenticationProvider.AssertionToken, Saml2ResponseValidatorResult> validator = mock(
				Converter.class);
		OpenSamlArtifactAuthenticationProvider provider = new OpenSamlArtifactAuthenticationProvider();
		// @formatter:off
		provider.setAssertionValidator((assertionToken) -> OpenSamlArtifactAuthenticationProvider.createDefaultAssertionValidator()
				.convert(assertionToken)
				.concat(validator.convert(assertionToken))
		);
		// @formatter:on
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = assertion();
		response.getAssertions().add(assertion);
		TestOpenSamlObjects.signed(response, TestSaml2X509Credentials.assertingPartySigningCredential(),
				ASSERTING_PARTY_ENTITY_ID);
		TestOpenSamlObjects.signed(artifactResponse, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		Saml2ArtifactAuthenticationToken token = token(artifactResponse, verifying(registration()));
		given(validator.convert(any(OpenSamlArtifactAuthenticationProvider.AssertionToken.class)))
				.willReturn(Saml2ResponseValidatorResult.success());
		provider.authenticate(token);
		verify(validator).convert(any(OpenSamlArtifactAuthenticationProvider.AssertionToken.class));
	}

	@Test
	public void authenticateWhenDefaultConditionValidatorNotUsedThenSignatureStillChecked() {
		OpenSamlArtifactAuthenticationProvider provider = new OpenSamlArtifactAuthenticationProvider();
		provider.setAssertionValidator((assertionToken) -> Saml2ResponseValidatorResult.success());
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = assertion();
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.relyingPartyDecryptingCredential(),
				RELYING_PARTY_ENTITY_ID); // broken
		// signature
		response.getAssertions().add(assertion);
		TestOpenSamlObjects.signed(response, TestSaml2X509Credentials.assertingPartySigningCredential(),
				ASSERTING_PARTY_ENTITY_ID);

		Saml2ArtifactAuthenticationToken token = token(artifactResponse, verifying(registration()));
		// @formatter:off
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> provider.authenticate(token))
				.satisfies((error) -> assertThat(error.getSaml2Error().getErrorCode()).isEqualTo(Saml2ErrorCodes.INVALID_SIGNATURE));
		// @formatter:on
	}

	@Test
	public void authenticateWhenValidationContextCustomizedThenUsers() {
		Map<String, Object> parameters = new HashMap<>();
		parameters.put(SAML2AssertionValidationParameters.SC_VALID_RECIPIENTS, Collections.singleton("blah"));
		ValidationContext context = mock(ValidationContext.class);
		given(context.getStaticParameters()).willReturn(parameters);
		OpenSamlArtifactAuthenticationProvider provider = new OpenSamlArtifactAuthenticationProvider();
		provider.setAssertionValidator(
				OpenSamlArtifactAuthenticationProvider.createDefaultAssertionValidator((assertionToken) -> context));
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = assertion();
		response.getAssertions().add(assertion);
		TestOpenSamlObjects.signed(response, TestSaml2X509Credentials.assertingPartySigningCredential(),
				ASSERTING_PARTY_ENTITY_ID);
		TestOpenSamlObjects.signed(artifactResponse, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		Saml2ArtifactAuthenticationToken token = token(artifactResponse, verifying(registration()));
		// @formatter:off
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> provider.authenticate(token)).isInstanceOf(Saml2AuthenticationException.class)
				.satisfies((error) -> assertThat(error).hasMessageContaining("Invalid assertion"));
		// @formatter:on
		verify(context, atLeastOnce()).getStaticParameters();
	}

	@Test
	public void authenticateWithSHA1SignatureThenItSucceeds() throws Exception {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = TestOpenSamlObjects.signed(assertion(),
				TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID,
				SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		response.getAssertions().add(assertion);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		this.provider.authenticate(token);
	}

	@Test
	public void setAssertionValidatorWhenNullThenIllegalArgument() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.provider.setAssertionValidator(null));
		// @formatter:on
	}

	@Test
	public void createDefaultResponseAuthenticationConverterWhenResponseThenConverts() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = TestOpenSamlObjects.signedResponseWithOneAssertion();

		Saml2ArtifactAuthenticationToken token = token(artifactResponse, verifying(registration()));
		ResponseToken responseToken = new ResponseToken(response, artifactResponse, token);
		Saml2Authentication authentication = OpenSamlArtifactAuthenticationProvider
				.createDefaultResponseAuthenticationConverter().convert(responseToken);
		assertThat(authentication.getName()).isEqualTo("test@saml.user");
	}

	@Test
	public void authenticateWhenResponseAuthenticationConverterConfiguredThenUses() {
		Converter<ResponseToken, Saml2Authentication> authenticationConverter = mock(Converter.class);
		OpenSamlArtifactAuthenticationProvider provider = new OpenSamlArtifactAuthenticationProvider();
		provider.setResponseAuthenticationConverter(authenticationConverter);
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = TestOpenSamlObjects.signedResponseWithOneAssertion();
		artifactResponse.setMessage(response);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		provider.authenticate(token);
		verify(authenticationConverter).convert(any());
	}

	@Test
	public void setResponseAuthenticationConverterWhenNullThenIllegalArgument() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.provider.setResponseAuthenticationConverter(null));
		// @formatter:on
	}

	@Test
	public void setResponseElementsDecrypterWhenNullThenIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.provider.setResponseElementsDecrypter(null));
	}

	@Test
	public void setAssertionElementsDecrypterWhenNullThenIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.provider.setAssertionElementsDecrypter(null));
	}

	@Test
	public void authenticateWhenCustomResponseElementsDecrypterThenDecryptsResponse() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = assertion();
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		response.getEncryptedAssertions().add(new EncryptedAssertionBuilder().buildObject());
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		this.provider.setResponseElementsDecrypter((tuple) -> tuple.getResponse().getAssertions().add(assertion));
		Authentication authentication = this.provider.authenticate(token);
		assertThat(authentication.getName()).isEqualTo("test@saml.user");
	}

	@Test
	public void authenticateWhenCustomAssertionElementsDecrypterThenDecryptsAssertion() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = ((Response) artifactResponse.getMessage());
		Assertion assertion = assertion();
		EncryptedID id = new EncryptedIDBuilder().buildObject();
		id.setEncryptedData(new EncryptedDataBuilder().buildObject());
		assertion.getSubject().setEncryptedID(id);
		TestOpenSamlObjects.signed(assertion, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		response.getAssertions().add(assertion);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		this.provider.setAssertionElementsDecrypter((tuple) -> {
			NameID name = new NameIDBuilder().buildObject();
			name.setValue("decrypted name");
			tuple.getAssertion().getSubject().setNameID(name);
		});
		Authentication authentication = this.provider.authenticate(token);
		assertThat(authentication.getName()).isEqualTo("decrypted name");
	}

	@Test
	public void authenticateWhenArtifactResponseStatusIsNotSuccessThenFails() {
		ArtifactResponse artifactResponse = TestOpenSamlObjects.signedArtifactResponseWithOneAssertion(
				(r) -> r.setStatus(TestOpenSamlObjects.status(StatusCode.AUTHN_FAILED)));
		Saml2ArtifactAuthenticationToken token = token(artifactResponse, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.INVALID_RESPONSE, "Invalid status"));
	}

	@Test
	public void authenticateWhenResponseStatusIsNotSuccessThenFails() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = TestOpenSamlObjects.signedResponseWithOneAssertion(
				(r) -> r.setStatus(TestOpenSamlObjects.status(StatusCode.AUTHN_FAILED)));
		artifactResponse.setMessage(response);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		assertThatExceptionOfType(Saml2AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(token))
				.satisfies(errorOf(Saml2ErrorCodes.INVALID_RESPONSE, "Invalid status"));
	}
	
	@Test
	public void authenticateWhenResponseStatusIsSuccessThenSucceeds() {
		ArtifactResponse artifactResponse = artifactResponse();
		Response response = TestOpenSamlObjects
				.signedResponseWithOneAssertion((r) -> r.setStatus(TestOpenSamlObjects.successStatus()));
		artifactResponse.setMessage(response);
		Saml2ArtifactAuthenticationToken token = signedToken(artifactResponse, verifying(registration()));
		Authentication authentication = this.provider.authenticate(token);
		assertThat(authentication.getName()).isEqualTo("test@saml.user");
	}

	private <T extends XMLObject> T build(QName qName) {
		return (T) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(qName).buildObject(qName);
	}

	private String serialize(XMLObject object) {
		try {
			Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
			Element element = marshaller.marshall(object);
			return SerializeSupport.nodeToString(element);
		}
		catch (MarshallingException ex) {
			throw new Saml2Exception(ex);
		}
	}

	private Consumer<Saml2AuthenticationException> errorOf(String errorCode) {
		return errorOf(errorCode, null);
	}

	private Consumer<Saml2AuthenticationException> errorOf(String errorCode, String description) {
		return (ex) -> {
			assertThat(ex.getError().getErrorCode()).isEqualTo(errorCode);
			if (StringUtils.hasText(description)) {
				assertThat(ex.getError().getDescription()).contains(description);
			}
		};
	}

	private ArtifactResponse artifactResponse() {
		ArtifactResponse artifactResponse = TestOpenSamlObjects.artifactResponse();
		artifactResponse.setIssueInstant(DateTime.now());
		return artifactResponse;
	}

	private ArtifactResponse artifactResponse(String destination, String issuerEntityId) {
		ArtifactResponse artifactResponse = TestOpenSamlObjects.artifactResponse(destination, issuerEntityId);
		artifactResponse.setIssueInstant(DateTime.now());
		return artifactResponse;
	}
	
	private Response response() {
		Response response = TestOpenSamlObjects.response();
		response.setIssueInstant(DateTime.now());
		return response;
	}

	private Response response(String destination, String issuerEntityId) {
		Response response = TestOpenSamlObjects.response(destination, issuerEntityId);
		response.setIssueInstant(DateTime.now());
		return response;
	}

	private Assertion assertion() {
		Assertion assertion = TestOpenSamlObjects.assertion();
		assertion.setIssueInstant(DateTime.now());
		for (SubjectConfirmation confirmation : assertion.getSubject().getSubjectConfirmations()) {
			SubjectConfirmationData data = confirmation.getSubjectConfirmationData();
			data.setNotBefore(DateTime.now().minus(Duration.millis(5 * 60 * 1000)));
			data.setNotOnOrAfter(DateTime.now().plus(Duration.millis(5 * 60 * 1000)));
		}
		Conditions conditions = assertion.getConditions();
		conditions.setNotBefore(DateTime.now().minus(Duration.millis(5 * 60 * 1000)));
		conditions.setNotOnOrAfter(DateTime.now().plus(Duration.millis(5 * 60 * 1000)));
		return assertion;
	}

	private List<AttributeStatement> attributeStatements() {
		List<AttributeStatement> attributeStatements = TestOpenSamlObjects.attributeStatements();
		AttributeBuilder attributeBuilder = new AttributeBuilder();
		Attribute registeredDateAttr = attributeBuilder.buildObject();
		registeredDateAttr.setName("registeredDate");
		XSDateTime registeredDate = new XSDateTimeBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
				XSDateTime.TYPE_NAME);
		registeredDate.setValue(DateTime.parse("1970-01-01T00:00:00Z"));
		registeredDateAttr.getAttributeValues().add(registeredDate);
		attributeStatements.get(0).getAttributes().add(registeredDateAttr);
		return attributeStatements;
	}

	private Saml2ArtifactAuthenticationToken token() {
		ArtifactResponse response = artifactResponse();
		RelyingPartyRegistration registration = verifying(registration()).build();
		return new Saml2ArtifactAuthenticationToken(registration, response);
	}

	private Saml2ArtifactAuthenticationToken token(ArtifactResponse response, RelyingPartyRegistration.Builder registration) {
		return new Saml2ArtifactAuthenticationToken(registration.build(), response);
	}

	private Saml2ArtifactAuthenticationToken signedToken(ArtifactResponse artifactResponse, RelyingPartyRegistration.Builder registration) {
		Response response = ((Response) artifactResponse.getMessage());
		TestOpenSamlObjects.signed(response, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		TestOpenSamlObjects.signed(artifactResponse, TestSaml2X509Credentials.assertingPartySigningCredential(),
				RELYING_PARTY_ENTITY_ID);
		return token(artifactResponse, registration);		
	}

	private RelyingPartyRegistration.Builder registration() {
		return TestRelyingPartyRegistrations.noCredentials().entityId(RELYING_PARTY_ENTITY_ID)
				.assertionConsumerServiceLocation(DESTINATION)
				.assertingPartyDetails((party) -> party.entityId(ASSERTING_PARTY_ENTITY_ID));
	}

	private RelyingPartyRegistration.Builder verifying(RelyingPartyRegistration.Builder builder) {
		return builder.assertingPartyDetails((party) -> party
				.verificationX509Credentials((c) -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())));
	}

	private RelyingPartyRegistration.Builder decrypting(RelyingPartyRegistration.Builder builder) {
		return builder
				.decryptionX509Credentials((c) -> c.add(TestSaml2X509Credentials.relyingPartyDecryptingCredential()));
	}

}
