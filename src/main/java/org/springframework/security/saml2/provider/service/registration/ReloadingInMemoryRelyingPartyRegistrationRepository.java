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

import java.time.Instant;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.util.Assert;

/**
 * @since 5.2
 */
public class ReloadingInMemoryRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository, Iterable<RelyingPartyRegistration> {

	private final Map<String, RelyingPartyRegistrationData> byRegistrationId;
	
	private final Timer timer;
	
    private long maxRefreshDelay = 14400000;

    private int minRefreshDelay = 300000;
	
	private static final Logger logger = LoggerFactory.getLogger(ReloadingInMemoryRelyingPartyRegistrationRepository.class);

	public ReloadingInMemoryRelyingPartyRegistrationRepository(Collection<Supplier<RelyingPartyRegistration>> registrationSuppliers) {
		timer = new Timer("MetadataReloadTimer");
		Assert.notEmpty(registrationSuppliers, "registrationSuppliers cannot be empty");
		this.byRegistrationId = createMappingToIdentityProvider(registrationSuppliers);
	}
	
	public ReloadingInMemoryRelyingPartyRegistrationRepository(Collection<Supplier<RelyingPartyRegistration>> registrationSuppliers, long maxRefreshDelay, int minRefreshDelay) {
        if (minRefreshDelay > maxRefreshDelay) {
            throw new Saml2Exception("Minimum refresh delay " + minRefreshDelay
                    + " is greater than maximum refresh delay " + maxRefreshDelay);
        }
		this.maxRefreshDelay = maxRefreshDelay;
		this.minRefreshDelay = minRefreshDelay;
		timer = new Timer("ReloadingInMemoryRelyingPartyRegistrationRepository");
		Assert.notEmpty(registrationSuppliers, "registrationSuppliers cannot be empty");
		this.byRegistrationId = createMappingToIdentityProvider(registrationSuppliers);
	}

	private Map<String, RelyingPartyRegistrationData> createMappingToIdentityProvider(
			Collection<Supplier<RelyingPartyRegistration>> rprss) {
		LinkedHashMap<String, RelyingPartyRegistrationData> result = new LinkedHashMap<>();
		for (Supplier<RelyingPartyRegistration> rprs : rprss) {
			Assert.notNull(rprs, "relying party registration suppliers collection cannot contain null values");
			RelyingPartyRegistration rpr = rprs.get();
			String key = rpr.getRegistrationId();
			Assert.notNull(key, "relying party identifier cannot be null");
			Assert.isNull(result.get(key), () -> "relying party duplicate identifier '" + key + "' detected.");
			RelyingPartyRegistrationData data = new RelyingPartyRegistrationData(rpr, rprs);
			result.put(key, data);
			schedule(data);
		}
		return result;
	}
	
	private void refresh(RelyingPartyRegistrationData data) {
		logger.debug("Beginning refresh metadata for registrationId={}", data.getRegistration().getRegistrationId());
		RelyingPartyRegistration rpr = data.getSupplier().get();
		String key = rpr.getRegistrationId();
		data = new RelyingPartyRegistrationData(rpr, data.getSupplier());
		byRegistrationId.replace(key, data);
		logger.debug("Refresh metadata for registrationId={} successfull", data.getRegistration().getRegistrationId());
		schedule(data);
	}
	
	private void schedule(RelyingPartyRegistrationData data) {
		logger.debug("Schedule refresh metadata for registrationId={}", data.getRegistration().getRegistrationId());
		Instant nextRefresh = calculateNextRefreshInstant(data);
		timer.schedule(new TimerTask() {

			@Override
			public void run() {
				refresh(data);	
			}
			
		}, nextRefresh.toEpochMilli() - System.currentTimeMillis());
		logger.debug("Refresh metadata for registrationId={} scheduled", data.getRegistration().getRegistrationId());
	}
	
	private Instant calculateNextRefreshInstant(RelyingPartyRegistrationData data) {
		logger.debug("Calculating refresh delay for registrationId={}", data.getRegistration().getRegistrationId());	
		Instant validUntil = data.getRegistration().getValidUntil();
		Instant now = Instant.now();
		long delay = 0;	
		if (validUntil == null) {
			logger.debug("No ValidUntil for registrationId={} available, using maxRefreshDelay={}", data.getRegistration().getRegistrationId(), maxRefreshDelay);
			delay = maxRefreshDelay;
		} else {	
			delay = validUntil.toEpochMilli() - System.currentTimeMillis();	
			if (delay > maxRefreshDelay) {
				logger.debug("Calculated delay={} for registrationId={} is higher than maxRefreshDelay={}, using maxRefreshDelay", delay, data.getRegistration().getRegistrationId(), maxRefreshDelay);	
				delay = maxRefreshDelay;
			}
			if (delay < 0) {				
				logger.debug("Calculated delay={} for registrationId={} is lower than minRefreshDelay={}, using minRefreshDelay", delay, data.getRegistration().getRegistrationId(), minRefreshDelay);	
				delay = minRefreshDelay;
			}
		}
		Instant nextRefreshInstant = now.plusMillis(delay);
		logger.debug("Calculated next refresh date={} for registrationId={}", nextRefreshInstant, data.getRegistration().getRegistrationId());	
		return nextRefreshInstant;
	}

	@Override
	public RelyingPartyRegistration findByRegistrationId(String id) {
		return this.byRegistrationId.get(id).registration;
	}

	@Override
	public Iterator<RelyingPartyRegistration> iterator() {
		return this.byRegistrationId.values().stream().map(RelyingPartyRegistrationData::getRegistration).iterator();
	}
	
	public void destroy() {
		this.timer.cancel();
	}

	private final class RelyingPartyRegistrationData {
		
		private final RelyingPartyRegistration registration;
		
		private final Supplier<RelyingPartyRegistration> supplier;

		public RelyingPartyRegistrationData(RelyingPartyRegistration registration, Supplier<RelyingPartyRegistration> supplier) {
			super();
			this.registration = registration;
			this.supplier = supplier;
		}

		public RelyingPartyRegistration getRegistration() {
			return registration;
		}

		public Supplier<RelyingPartyRegistration> getSupplier() {
			return supplier;
		}
	}
}
