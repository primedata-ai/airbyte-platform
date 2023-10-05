/*
 * Copyright (c) 2023 Airbyte, Inc., all rights reserved.
 */

package io.airbyte.server;

import io.airbyte.commons.auth.AuthRole;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.security.authentication.Authentication;
import io.micronaut.security.filters.AuthenticationFetcher;
import jakarta.inject.Singleton;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Token validator for internal Airbyte auth. This is used to authenticate internal requests between
 * Airbyte services. Traffic between internal services is assumed to be trusted, so this is not a
 * means of security, but rather a mechanism for identifying and granting roles to the service that
 * is making the internal request. The webapp proxy unsets the X-Airbyte-Auth header, so this header
 * will only be present on internal requests.
 **/

@Singleton
public class AuthorizeToken implements AuthenticationFetcher {

    private static final Logger log = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private boolean checkToken(String token) throws IOException {
        URL url = new URL("http://meta-router:8088/internal/auth");
        String bearerToken = "Bearer " + token;
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestProperty("Authorization", bearerToken);
        con.setRequestMethod("GET");

        int status = con.getResponseCode();
        log.info("Status: " + status);

        return status < 400;
    };

    @Override
    public Publisher<Authentication> fetchAuthentication(HttpRequest<?> request) {
        String header = request.getHeaders().get("X-Airbyte-Analytic-Source");
        if (header != null && header.equals("webapp")) {
            Optional<Cookie> token = request.getCookies().findCookie("AB-Auth-Token");
            if (token.isPresent()) {
                try {
                    if (checkToken(token.get().getValue())) {
                        return Flux.create(emitter -> {
                            emitter.next(Authentication.build("lav", AuthRole.buildAuthRolesSet(AuthRole.ADMIN)));
                            emitter.complete();
                        });
                    }
                } catch (IOException e) {
                    log.error("Error: " + e.getMessage());
                }
            }
            return Flux.empty();
        }

        return Flux.create(emitter -> {
            emitter.next(Authentication.build("lav", AuthRole.buildAuthRolesSet(AuthRole.ADMIN)));
            emitter.complete();
        });
    }
}
