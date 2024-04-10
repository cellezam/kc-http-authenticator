package de.cellezam.keycloak.authentication.httpauth;

import org.keycloak.models.AuthenticatorConfigModel;

import java.util.Optional;

final class HttpUserPasswordConfig {
    static final String LOGIN_ENDPOINT = "login_base_url";

    static final String SUCCESS_STATUS_CODE = "success_status_code";
    private final AuthenticatorConfigModel authenticatorConfigModel;

    HttpUserPasswordConfig(AuthenticatorConfigModel authenticatorConfigModel) {
        this.authenticatorConfigModel = authenticatorConfigModel;
    }

    String baseURL() {
        return Optional.ofNullable(authenticatorConfigModel)
            .map(it -> it.getConfig().getOrDefault(LOGIN_ENDPOINT, "").trim())
            .orElse("login");
    }

    String successStatusCode() {
        return Optional.ofNullable(authenticatorConfigModel)
            .map(it -> it.getConfig().getOrDefault(SUCCESS_STATUS_CODE, "200").trim())
            .orElse("200");
    }

}
