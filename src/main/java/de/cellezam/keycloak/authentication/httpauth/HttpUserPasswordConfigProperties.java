package de.cellezam.keycloak.authentication.httpauth;

import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

import static de.cellezam.keycloak.authentication.httpauth.HttpUserPasswordConfig.*;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

final class HttpUserPasswordConfigProperties {

    private static final ProviderConfigProperty LOGIN_BASE_URL = new ProviderConfigProperty(
        LOGIN_ENDPOINT,
        "Login endpoint",
        "Provide the full path of the login endpoint",
        STRING_TYPE,
        "http://localhost:3000/auth/login",
        false
    );

    private static final ProviderConfigProperty STATUS_CODE_SUCCESS = new ProviderConfigProperty(
        SUCCESS_STATUS_CODE,
        "Success Status Code",
        "Provide the status code which authorize the user to connect",
        STRING_TYPE,
        "200",
        false
    );

    static final List<ProviderConfigProperty> CONFIG_PROPERTIES = ProviderConfigurationBuilder.create()
        .property(LOGIN_BASE_URL)
        .property(STATUS_CODE_SUCCESS)
        .build();

}
