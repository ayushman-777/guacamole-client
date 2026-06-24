/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
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

package org.apache.guacamole.auth.openid;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.Inject;
import com.google.inject.Provider;
import com.google.inject.Singleton;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import javax.ws.rs.core.UriBuilder;
import org.apache.guacamole.auth.openid.conf.ConfigurationService;
import org.apache.guacamole.auth.openid.token.TokenValidationService;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.auth.sso.NonceService;
import org.apache.guacamole.auth.sso.SSOAuthenticationProviderService;
import org.apache.guacamole.auth.sso.user.SSOAuthenticatedUser;
import org.apache.guacamole.form.Field;
import org.apache.guacamole.form.RedirectField;
import org.apache.guacamole.language.TranslatableMessage;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.credentials.CredentialsInfo;
import org.apache.guacamole.net.auth.credentials.GuacamoleInvalidCredentialsException;
import org.jose4j.jwt.JwtClaims;

/**
 * Service that authenticates Guacamole users by processing OpenID tokens.
 */
@Singleton
public class AuthenticationProviderService implements SSOAuthenticationProviderService {

    /**
     * The standard HTTP parameter which will be included within the URL by all
     * OpenID services upon successful authentication and redirect.
     */
    public static final String TOKEN_PARAMETER_NAME = "id_token";

    /**
     * The standard HTTP parameter which will be included within the URL by all
     * OpenID services upon successful authorization code authentication.
     */
    public static final String CODE_PARAMETER_NAME = "code";

    /**
     * OpenID response type for authorization code flow.
     */
    private static final String CODE_RESPONSE_TYPE = "code";

    /**
     * JSON parser for OpenID token endpoint responses.
     */
    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();

    /**
     * Service for retrieving OpenID configuration information.
     */
    @Inject
    private ConfigurationService confService;

    /**
     * Service for validating and generating unique nonce values.
     */
    @Inject
    private NonceService nonceService;

    /**
     * Service for validating received ID tokens.
     */
    @Inject
    private TokenValidationService tokenService;

    /**
     * Provider for AuthenticatedUser objects.
     */
    @Inject
    private Provider<SSOAuthenticatedUser> authenticatedUserProvider;

    @Override
    public SSOAuthenticatedUser authenticateUser(Credentials credentials)
            throws GuacamoleException {

        String username = null;
        Set<String> groups = null;
        Map<String,String> tokens = Collections.emptyMap();

        // Validate OpenID token in request, if present, and derive username
        String token = credentials.getParameter(TOKEN_PARAMETER_NAME);

        // If authorization code flow is being used, exchange the returned code
        // for an ID token before continuing with normal validation.
        if (token == null) {
            String code = credentials.getParameter(CODE_PARAMETER_NAME);
            if (code != null)
                token = exchangeCodeForToken(code);
        }

        if (token != null) {
            JwtClaims claims = tokenService.validateToken(token);
            if (claims != null) {
                username = tokenService.processUsername(claims);
                groups = tokenService.processGroups(claims);
                tokens = tokenService.processAttributes(claims);
            }
        }

        // If the username was successfully retrieved from the token, produce
        // authenticated user
        if (username != null) {

            // Create corresponding authenticated user
            SSOAuthenticatedUser authenticatedUser = authenticatedUserProvider.get();
            authenticatedUser.init(username, credentials, groups, tokens);
            return authenticatedUser;

        }

        // Request OpenID token (will automatically redirect the user to the
        // OpenID authorization page via JavaScript)
        throw new GuacamoleInvalidCredentialsException("Invalid login.",
            new CredentialsInfo(Arrays.asList(new Field[] {
                new RedirectField(getResponseParameterName(), getLoginURI(),
                        new TranslatableMessage("LOGIN.INFO_IDP_REDIRECT_PENDING"))
            }))
        );

    }

    @Override
    public URI getLoginURI() throws GuacamoleException {
        return UriBuilder.fromUri(confService.getAuthorizationEndpoint())
                .queryParam("scope", confService.getScope())
                .queryParam("response_type", confService.getResponseType())
                .queryParam("client_id", confService.getClientID())
                .queryParam("redirect_uri", confService.getRedirectURI())
                .queryParam("nonce", nonceService.generate(confService.getMaxNonceValidity() * 60000L))
                .build();
    }

    /**
     * Returns the credential parameter expected from the OpenID provider for
     * the configured response type.
     *
     * @return
     *     The credential parameter expected from the OpenID provider.
     *
     * @throws GuacamoleException
     *     If guacamole.properties cannot be parsed.
     */
    private String getResponseParameterName() throws GuacamoleException {
        if (CODE_RESPONSE_TYPE.equals(confService.getResponseType()))
            return CODE_PARAMETER_NAME;

        return TOKEN_PARAMETER_NAME;
    }

    /**
     * Exchanges the given authorization code for an ID token using the OpenID
     * token endpoint.
     *
     * @param code
     *     The authorization code received from the OpenID provider.
     *
     * @return
     *     The ID token returned by the OpenID provider.
     *
     * @throws GuacamoleException
     *     If the token endpoint cannot be contacted or returns an invalid
     *     response.
     */
    private String exchangeCodeForToken(String code) throws GuacamoleException {

        HttpURLConnection connection = null;

        try {
            connection = (HttpURLConnection) confService.getTokenEndpoint().toURL().openConnection();
            connection.setConnectTimeout(15000);
            connection.setReadTimeout(15000);
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            String clientID = confService.getClientID();
            String clientSecret = confService.getClientSecret();

            if (clientSecret != null && !clientSecret.isEmpty()) {
                String credentials = clientID + ":" + clientSecret;
                String basicAuth = Base64.getEncoder().encodeToString(
                        credentials.getBytes(StandardCharsets.UTF_8));
                connection.setRequestProperty("Authorization", "Basic " + basicAuth);
            }

            Map<String, String> parameters = new HashMap<>();
            parameters.put("grant_type", "authorization_code");
            parameters.put("code", code);
            parameters.put("redirect_uri", confService.getRedirectURI().toString());

            if (clientSecret == null || clientSecret.isEmpty())
                parameters.put("client_id", clientID);

            byte[] requestBody = formEncode(parameters).getBytes(StandardCharsets.UTF_8);
            connection.setRequestProperty("Content-Length", Integer.toString(requestBody.length));

            try (OutputStream output = connection.getOutputStream()) {
                output.write(requestBody);
            }

            int responseCode = connection.getResponseCode();
            String responseBody = readResponseBody(connection, responseCode);

            if (responseCode < 200 || responseCode >= 300)
                throw new GuacamoleServerException("OpenID token endpoint returned HTTP "
                        + responseCode + ": " + responseBody);

            Map<String, Object> tokenResponse = JSON_MAPPER.readValue(responseBody,
                    new TypeReference<Map<String, Object>>() {});

            Object idToken = tokenResponse.get(TOKEN_PARAMETER_NAME);
            if (idToken instanceof String && !((String) idToken).isEmpty())
                return (String) idToken;

            throw new GuacamoleServerException("OpenID token endpoint response did not contain an ID token.");

        }
        catch (IOException e) {
            throw new GuacamoleServerException("Unable to exchange OpenID authorization code.", e);
        }
        finally {
            if (connection != null)
                connection.disconnect();
        }

    }

    /**
     * Encodes the given parameters as an application/x-www-form-urlencoded
     * request body.
     *
     * @param parameters
     *     The parameters to encode.
     *
     * @return
     *     The encoded form body.
     */
    private String formEncode(Map<String, String> parameters) {
        StringBuilder body = new StringBuilder();

        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            if (body.length() > 0)
                body.append('&');

            body.append(urlEncode(entry.getKey()));
            body.append('=');
            body.append(urlEncode(entry.getValue()));
        }

        return body.toString();
    }

    /**
     * Encodes the given value for use in an application/x-www-form-urlencoded
     * request body.
     *
     * @param value
     *     The value to encode.
     *
     * @return
     *     The encoded value.
     */
    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /**
     * Reads the response body from the given HTTP connection.
     *
     * @param connection
     *     The HTTP connection to read from.
     *
     * @param responseCode
     *     The HTTP response code returned by the connection.
     *
     * @return
     *     The response body.
     *
     * @throws IOException
     *     If the response body cannot be read.
     */
    private String readResponseBody(HttpURLConnection connection, int responseCode)
            throws IOException {

        InputStream stream = responseCode >= 400
                ? connection.getErrorStream()
                : connection.getInputStream();

        if (stream == null)
            return "";

        byte[] bytes;
        try (InputStream input = stream) {
            bytes = input.readAllBytes();
        }

        return new String(bytes, StandardCharsets.UTF_8);
    }

    @Override
    public URI getLogoutURI(String idToken) throws GuacamoleException {

        // If no logout endpoint is configured, return null
        URI logoutEndpoint = confService.getLogoutEndpoint();
        if (logoutEndpoint == null)
            return null;

        // Build the logout URI with appropriate parameters
        UriBuilder logoutUriBuilder = UriBuilder.fromUri(logoutEndpoint);

        /*
         * This Cognito Hosted UI rejects browser logout redirects for this
         * app client despite the redirect URI being registered. Avoid sending
         * users to Cognito's invalid-request page and return them to the
         * configured post-logout page instead.
         */
        if (isCognitoLogoutEndpoint(logoutEndpoint)) {
            return confService.getPostLogoutRedirectURI();
        }

        logoutUriBuilder.queryParam("post_logout_redirect_uri",
                confService.getPostLogoutRedirectURI());

        // Add id_token_hint if available, otherwise add client_id
        if (idToken != null && !idToken.isEmpty())
            logoutUriBuilder.queryParam("id_token_hint", idToken);
        else
            logoutUriBuilder.queryParam("client_id", confService.getClientID());

        return logoutUriBuilder.build();
    }

    private boolean isCognitoLogoutEndpoint(URI logoutEndpoint) {
        String host = logoutEndpoint.getHost();
        return host != null && host.endsWith(".amazoncognito.com");
    }

    @Override
    public void shutdown() {
        // Nothing to clean up
    }

}
