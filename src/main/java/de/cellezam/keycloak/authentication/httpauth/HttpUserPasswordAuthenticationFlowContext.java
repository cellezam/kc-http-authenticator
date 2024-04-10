package de.cellezam.keycloak.authentication.httpauth;

import org.keycloak.authentication.AuthenticationFlowContext;

final class HttpUserPasswordAuthenticationFlowContext {

    private final AuthenticationFlowContext context;
    private HttpUserPasswordConfig config;

    HttpUserPasswordAuthenticationFlowContext(AuthenticationFlowContext context) {
        this.context = context;
    }

    HttpUserPasswordConfig config() {
        if (config == null) {
            config = new HttpUserPasswordConfig(context.getAuthenticatorConfig());
        }
        return config;
    }
}
