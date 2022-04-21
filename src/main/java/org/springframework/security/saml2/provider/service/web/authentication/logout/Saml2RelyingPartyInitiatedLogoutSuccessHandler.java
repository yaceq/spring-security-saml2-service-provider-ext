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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.function.Function;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.impl.LogoutResponseMarshaller;
import org.springframework.core.log.LogMessage;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidatorParameters;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.soap.HttpSOAPClient;
import org.springframework.security.saml2.soap.SOAPClient;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;

/**
 * A success handler for issuing a SAML 2.0 Logout Request to the the SAML 2.0
 * Asserting Party
 *
 * @author Josh Cummings
 * @since 5.6
 */
public final class Saml2RelyingPartyInitiatedLogoutSuccessHandler implements LogoutSuccessHandler {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final Log logger = LogFactory.getLog(getClass());

	private final Saml2LogoutRequestResolver logoutRequestResolver;

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private Saml2LogoutRequestRepository logoutRequestRepository = new HttpSessionLogoutRequestRepository();

	private RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	private Saml2LogoutResponseValidator logoutResponseValidator;

	private LogoutSuccessHandler logoutSuccessHandler;

	private final LogoutResponseMarshaller logoutResponseMarshaller;

	private SOAPClient soapClient = new HttpSOAPClient();

	/**
	 * Constructs a {@link Saml2RelyingPartyInitiatedLogoutSuccessHandler} using the
	 * provided parameters
	 * 
	 * @param logoutRequestResolver the {@link Saml2LogoutRequestResolver} to use
	 */
	public Saml2RelyingPartyInitiatedLogoutSuccessHandler(Saml2LogoutRequestResolver logoutRequestResolver,
			RelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
			LogoutSuccessHandler logoutSuccessHandler, Saml2LogoutResponseValidator logoutResponseValidator) {
		this.logoutRequestResolver = logoutRequestResolver;
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
		this.logoutResponseValidator = logoutResponseValidator;
		this.logoutSuccessHandler = logoutSuccessHandler;

		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.logoutResponseMarshaller = (LogoutResponseMarshaller) registry.getMarshallerFactory()
				.getMarshaller(LogoutResponse.DEFAULT_ELEMENT_NAME);
	}

	/**
	 * Produce and send a SAML 2.0 Logout Response based on the SAML 2.0 Logout
	 * Request received from the asserting party
	 * 
	 * @param request        the HTTP request
	 * @param response       the HTTP response
	 * @param authentication the current principal details
	 * @throws IOException      when failing to write to the response
	 * @throws ServletException
	 */
	@Override
	public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
			throws IOException, ServletException {
		Saml2LogoutRequest logoutRequest = this.logoutRequestResolver.resolve(request, authentication);
		if (logoutRequest == null) {
			this.logger.trace("Returning 401 since no logout request generated");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}
		if (logoutRequest.getBinding() == Saml2MessageBinding.REDIRECT) {
			this.logoutRequestRepository.saveLogoutRequest(logoutRequest, request, response);
			doRedirect(request, response, logoutRequest);
		} else if (logoutRequest.getBinding() == Saml2MessageBinding.POST) {
			this.logoutRequestRepository.saveLogoutRequest(logoutRequest, request, response);
			doPost(response, logoutRequest);
		} else {
			doSOAP(request, response, logoutRequest, authentication);
		}
	}

	/**
	 * Use this {@link Saml2LogoutRequestRepository} for saving the SAML 2.0 Logout
	 * Request
	 * 
	 * @param logoutRequestRepository the {@link Saml2LogoutRequestRepository} to
	 *                                use
	 */
	public void setLogoutRequestRepository(Saml2LogoutRequestRepository logoutRequestRepository) {
		Assert.notNull(logoutRequestRepository, "logoutRequestRepository cannot be null");
		this.logoutRequestRepository = logoutRequestRepository;
	}

	private void doRedirect(HttpServletRequest request, HttpServletResponse response, Saml2LogoutRequest logoutRequest)
			throws IOException {
		String location = logoutRequest.getLocation();
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(location);
		addParameter(Saml2ParameterNames.SAML_REQUEST, logoutRequest::getParameter, uriBuilder);
		addParameter(Saml2ParameterNames.RELAY_STATE, logoutRequest::getParameter, uriBuilder);
		addParameter(Saml2ParameterNames.SIG_ALG, logoutRequest::getParameter, uriBuilder);
		addParameter(Saml2ParameterNames.SIGNATURE, logoutRequest::getParameter, uriBuilder);
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.build(true).toUriString());
	}

	private void addParameter(String name, Function<String, String> parameters, UriComponentsBuilder builder) {
		Assert.hasText(name, "name cannot be empty or null");
		if (StringUtils.hasText(parameters.apply(name))) {
			builder.queryParam(UriUtils.encode(name, StandardCharsets.ISO_8859_1),
					UriUtils.encode(parameters.apply(name), StandardCharsets.ISO_8859_1));
		}
	}

	private void doPost(HttpServletResponse response, Saml2LogoutRequest logoutRequest) throws IOException {
		String location = logoutRequest.getLocation();
		String saml = logoutRequest.getSamlRequest();
		String relayState = logoutRequest.getRelayState();
		String html = createSamlPostRequestFormData(location, saml, relayState);
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.getWriter().write(html);
	}

	private String createSamlPostRequestFormData(String location, String saml, String relayState) {
		StringBuilder html = new StringBuilder();
		html.append("<!DOCTYPE html>\n");
		html.append("<html>\n").append("    <head>\n");
		html.append("        <meta charset=\"utf-8\" />\n");
		html.append("    </head>\n");
		html.append("    <body onload=\"document.forms[0].submit()\">\n");
		html.append("        <noscript>\n");
		html.append("            <p>\n");
		html.append("                <strong>Note:</strong> Since your browser does not support JavaScript,\n");
		html.append("                you must press the Continue button once to proceed.\n");
		html.append("            </p>\n");
		html.append("        </noscript>\n");
		html.append("        \n");
		html.append("        <form action=\"");
		html.append(location);
		html.append("\" method=\"post\">\n");
		html.append("            <div>\n");
		html.append("                <input type=\"hidden\" name=\"SAMLRequest\" value=\"");
		html.append(HtmlUtils.htmlEscape(saml));
		html.append("\"/>\n");
		if (StringUtils.hasText(relayState)) {
			html.append("                <input type=\"hidden\" name=\"RelayState\" value=\"");
			html.append(HtmlUtils.htmlEscape(relayState));
			html.append("\"/>\n");
		}
		html.append("            </div>\n");
		html.append("            <noscript>\n");
		html.append("                <div>\n");
		html.append("                    <input type=\"submit\" value=\"Continue\"/>\n");
		html.append("                </div>\n");
		html.append("            </noscript>\n");
		html.append("        </form>\n");
		html.append("        \n");
		html.append("    </body>\n");
		html.append("</html>");
		return html.toString();
	}

	private void doSOAP(HttpServletRequest request, HttpServletResponse response, Saml2LogoutRequest logoutRequest, Authentication authentication)
			throws IOException, ServletException {
		String location = logoutRequest.getLocation();
		XMLObject req = logoutRequest.getXmlSamlRequest();
		XMLObject resp = this.soapClient.send(req, location, null);
		validateSoapResponse(request, response, logoutRequest, resp, authentication);
	}

	private void validateSoapResponse(HttpServletRequest request, HttpServletResponse response,
			Saml2LogoutRequest logoutRequest, XMLObject resp, Authentication authentication) throws IOException, ServletException {
		RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request,
				logoutRequest.getRelyingPartyRegistrationId());
		if (registration == null) {
			this.logger
					.trace("Did not process logout request since failed to find associated RelyingPartyRegistration");
			Saml2Error error = new Saml2Error(Saml2ErrorCodes.RELYING_PARTY_REGISTRATION_NOT_FOUND,
					"Failed to find associated RelyingPartyRegistration");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, error.toString());
			return;
		}
		if (!(resp instanceof LogoutResponse)) {
			this.logger
					.trace("Did not process logout request because response is not LogoutResponse");
			Saml2Error error = new Saml2Error(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA,
					"Response is not instance of LogoutResponse");
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, error.toString());
			return;
		}
		Saml2LogoutResponse logoutResponse = Saml2LogoutResponse.withRelyingPartyRegistration(registration)
				.samlResponse(Saml2Utils.samlEncode(serialize((LogoutResponse)resp).getBytes())).build();
		Saml2LogoutResponseValidatorParameters parameters = new Saml2LogoutResponseValidatorParameters(logoutResponse,
				logoutRequest, registration);
		Saml2LogoutValidatorResult result = this.logoutResponseValidator.validate(parameters);
		if (result.hasErrors()) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, result.getErrors().iterator().next().toString());
			this.logger.debug(LogMessage.format("Failed to validate LogoutResponse: %s", result.getErrors()));
			return;
		}
		this.logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
	}
	

	private String serialize(LogoutResponse logoutResponse) {
		try {
			Element element = this.logoutResponseMarshaller.marshall(logoutResponse);
			return SerializeSupport.nodeToString(element);
		}
		catch (MarshallingException ex) {
			throw new Saml2Exception(ex);
		}
	}

	public void setSoapClient(SOAPClient soapClient) {
		Assert.notNull(soapClient, "soapClient cannot be null");
		this.soapClient = soapClient;
	}
}
