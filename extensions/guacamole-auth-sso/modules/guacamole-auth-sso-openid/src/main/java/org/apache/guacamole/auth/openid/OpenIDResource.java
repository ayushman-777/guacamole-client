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

import com.google.inject.Inject;
import java.net.URI;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.auth.openid.conf.ConfigurationService;
import org.apache.guacamole.auth.sso.SSOResource;

/**
 * OpenID resource which exposes both the standard login redirect and a custom
 * logout redirect that terminates the upstream IdP session.
 */
public class OpenIDResource extends SSOResource {

    @Inject
    private ConfigurationService confService;

    /**
     * Redirects the browser to the OpenID provider logout endpoint. This is
     * intended for providers like AWS Cognito where logging out of Guacamole
     * alone does not destroy the provider's SSO session.
     *
     * @return
     *     An HTTP redirect response to the OpenID provider logout endpoint.
     *
     * @throws GuacamoleException
     *     If the logout redirect URI cannot be constructed.
     */
    @GET
    @Path("logout")
    public Response redirectToIdentityProviderLogout() throws GuacamoleException {
        URI logoutURI = UriBuilder.fromUri(confService.getProviderLogoutEndpoint())
                .queryParam("client_id", confService.getClientID())
                .queryParam("logout_uri", confService.getPostLogoutURI())
                .build();
        return Response.seeOther(logoutURI).build();
    }

}
