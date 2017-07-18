/*
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jasig.cas.client.authentication;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.jasig.cas.client.Protocol;
import org.jasig.cas.client.configuration.ConfigurationKeys;
import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.util.ReflectUtils;
import org.jasig.cas.client.validation.Assertion;

/**
 * Filter implementation to intercept all requests and attempt to authenticate
 * the user by redirecting them to CAS (unless the user has a ticket).
 * <p>
 * This filter allows you to specify the following parameters (at either the
 * context-level or the filter-level):
 * <ul>
 * <li><code>casServerLoginUrl</code> - the url to log into CAS, i.e.
 * https://cas.rutgers.edu/login</li>
 * <li><code>renew</code> - true/false on whether to use renew or not.</li>
 * <li><code>gateway</code> - true/false on whether to use gateway or not.</li>
 * </ul>
 *
 * <p>
 * Please see AbstractCasFilter for additional properties.
 * </p>
 * <p>
 * 修改:1.增加ajax请求处理<br>
 * 2.增加获取自定义filter参数 <br>
 * 3.增加service url构造方法用于自定义继承
 * 
 * @author Scott Battaglia
 * @author Misagh Moayyed
 * @since 3.0
 */
public class AuthenticationFilter extends AbstractCasFilter {
	/**
	 * The URL to the CAS Server login.
	 */
	private String casServerLoginUrl;

	/**
	 * Whether to send the renew request or not.
	 */
	private boolean renew = false;

	/**
	 * Whether to send the gateway request or not.
	 */
	private boolean gateway = false;

	private GatewayResolver gatewayStorage = new DefaultGatewayResolverImpl();

	private AuthenticationRedirectStrategy authenticationRedirectStrategy = new DefaultAuthenticationRedirectStrategy();

	private UrlPatternMatcherStrategy ignoreUrlPatternMatcherStrategyClass = null;

	private String ajaxMsg;

	private static final Map<String, Class<? extends UrlPatternMatcherStrategy>> PATTERN_MATCHER_TYPES = new HashMap<String, Class<? extends UrlPatternMatcherStrategy>>();

	static {
		PATTERN_MATCHER_TYPES.put("CONTAINS", ContainsPatternUrlPatternMatcherStrategy.class);
		PATTERN_MATCHER_TYPES.put("REGEX", RegexUrlPatternMatcherStrategy.class);
		PATTERN_MATCHER_TYPES.put("EXACT", ExactUrlPatternMatcherStrategy.class);
	}

	public AuthenticationFilter() {
		this(Protocol.CAS2);
	}

	protected AuthenticationFilter(final Protocol protocol) {
		super(protocol);
	}

	protected void initInternal(final FilterConfig filterConfig) throws ServletException {
		if (!isIgnoreInitConfiguration()) {
			super.initInternal(filterConfig);
			setCasServerLoginUrl(getString(ConfigurationKeys.CAS_SERVER_LOGIN_URL));
			setRenew(getBoolean(ConfigurationKeys.RENEW));
			setGateway(getBoolean(ConfigurationKeys.GATEWAY));

			final String ignorePattern = getString(ConfigurationKeys.IGNORE_PATTERN);
			final String ignoreUrlPatternType = getString(ConfigurationKeys.IGNORE_URL_PATTERN_TYPE);

			initParam(filterConfig);

			if (ignorePattern != null) {
				final Class<? extends UrlPatternMatcherStrategy> ignoreUrlMatcherClass = PATTERN_MATCHER_TYPES
						.get(ignoreUrlPatternType);
				if (ignoreUrlMatcherClass != null) {
					this.ignoreUrlPatternMatcherStrategyClass = ReflectUtils
							.newInstance(ignoreUrlMatcherClass.getName());
				} else {
					try {
						logger.trace("Assuming {} is a qualified class name...", ignoreUrlPatternType);
						this.ignoreUrlPatternMatcherStrategyClass = ReflectUtils.newInstance(ignoreUrlPatternType);
					} catch (final IllegalArgumentException e) {
						logger.error("Could not instantiate class [{}]", ignoreUrlPatternType, e);
					}
				}
				if (this.ignoreUrlPatternMatcherStrategyClass != null) {
					this.ignoreUrlPatternMatcherStrategyClass.setPattern(ignorePattern);
				}
			}

			final Class<? extends GatewayResolver> gatewayStorageClass = getClass(
					ConfigurationKeys.GATEWAY_STORAGE_CLASS);

			if (gatewayStorageClass != null) {
				setGatewayStorage(ReflectUtils.newInstance(gatewayStorageClass));
			}

			final Class<? extends AuthenticationRedirectStrategy> authenticationRedirectStrategyClass = getClass(
					ConfigurationKeys.AUTHENTICATION_REDIRECT_STRATEGY_CLASS);

			if (authenticationRedirectStrategyClass != null) {
				this.authenticationRedirectStrategy = ReflectUtils.newInstance(authenticationRedirectStrategyClass);
			}
		}
	}

	public void init() {
		super.init();
		CommonUtils.assertNotNull(this.casServerLoginUrl, "casServerLoginUrl cannot be null.");
	}

	public final void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
			final FilterChain filterChain) throws IOException, ServletException {

		final HttpServletRequest request = (HttpServletRequest) servletRequest;
		final HttpServletResponse response = (HttpServletResponse) servletResponse;

		if (isRequestUrlExcluded(request)) {
			logger.debug("Request is ignored.");
			filterChain.doFilter(request, response);
			return;
		}

		final HttpSession session = request.getSession(false);
		final Assertion assertion = session != null ? (Assertion) session.getAttribute(CONST_CAS_ASSERTION) : null;

		if (assertion != null) {
			filterChain.doFilter(request, response);
			return;
		}

		final String serviceUrl = constructServiceUrl(request, response);
		final String ticket = retrieveTicketFromRequest(request);
		final boolean wasGatewayed = this.gateway && this.gatewayStorage.hasGatewayedAlready(request, serviceUrl);

		if (CommonUtils.isNotBlank(ticket) || wasGatewayed) {
			filterChain.doFilter(request, response);
			return;
		}

		final String modifiedServiceUrl;

		logger.debug("no ticket and no assertion found");
		if (this.gateway) {
			logger.debug("setting gateway attribute in session");
			modifiedServiceUrl = this.gatewayStorage.storeGatewayInformation(request, serviceUrl);
		} else {
			modifiedServiceUrl = serviceUrl;
		}

		logger.debug("Constructed service url: {}", modifiedServiceUrl);

		afterFoward(request, response, modifiedServiceUrl);

	}

	/**
	 * 自定义配置参数
	 * 
	 * @param filterConfig
	 */
	protected void initParam(final FilterConfig filterConfig) {
		ajaxMsg = getString(ConfigurationKeys.AJAX_MSG);
	}

	protected void afterFoward(final HttpServletRequest request, final HttpServletResponse response, String serviceUrl)
			throws IOException {
		if (isAjaxRequest(request)) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			PrintWriter out = response.getWriter();
			response.setContentType(MIME_TYPE_JSON[0]);
			out.print(ajaxMsg);
			out.close();
		} else {
			final String urlToRedirectTo = CommonUtils.constructRedirectUrl(this.casServerLoginUrl,
					getProtocol().getServiceParameterName(), serviceUrl, this.renew, this.gateway);
			sendRedirect(request, response, urlToRedirectTo);
		}
	}
	
	protected void sendRedirect(final HttpServletRequest request, final HttpServletResponse response,
			String urlToRedirectTo) throws IOException {
		logger.debug("redirecting to \"{}\"", urlToRedirectTo);
		this.authenticationRedirectStrategy.redirect(request, response, urlToRedirectTo);
	}
	
	public final void setRenew(final boolean renew) {
		this.renew = renew;
	}

	public final void setGateway(final boolean gateway) {
		this.gateway = gateway;
	}

	public final void setCasServerLoginUrl(final String casServerLoginUrl) {
		this.casServerLoginUrl = casServerLoginUrl;
	}

	public final void setGatewayStorage(final GatewayResolver gatewayStorage) {
		this.gatewayStorage = gatewayStorage;
	}

	private boolean isRequestUrlExcluded(final HttpServletRequest request) {
		if (this.ignoreUrlPatternMatcherStrategyClass == null) {
			return false;
		}

		final StringBuffer urlBuffer = request.getRequestURL();
		if (request.getQueryString() != null) {
			urlBuffer.append("?").append(request.getQueryString());
		}
		final String requestUri = urlBuffer.toString();
		return this.ignoreUrlPatternMatcherStrategyClass.matches(requestUri);
	}

	public final void setIgnoreUrlPatternMatcherStrategyClass(
			final UrlPatternMatcherStrategy ignoreUrlPatternMatcherStrategyClass) {
		this.ignoreUrlPatternMatcherStrategyClass = ignoreUrlPatternMatcherStrategyClass;
	}

	final static String AJAX_REQUEST_FLAG = "x-requested-with";
	final static String AJAX_REQUEST_VALUE = "XMLHttpRequest";
	final String[] MIME_TYPE_JSON = { "application/json", "text/json" };

	/**
	 * 判断请求是否是一个ajax请求
	 * <p>
	 * 请求头含x-requested-with=XMLHttpRequest
	 * 
	 * @param request
	 *            HttpServletRequest
	 * @return
	 */
	public boolean isAjaxRequest(HttpServletRequest request) {
		if (AJAX_REQUEST_FLAG.equalsIgnoreCase(request.getHeader(AJAX_REQUEST_VALUE))) {
			return true;
		} else {
			String headAccept = request.getHeader("accept");
			if (request.getServletPath().endsWith("json")) {
				return true;
			} else if (headAccept != null
					&& (headAccept.indexOf(MIME_TYPE_JSON[0]) >= 0 || headAccept.indexOf(MIME_TYPE_JSON[1]) >= 0)) {
				return true;
			}
			return false;
		}
	}

}
