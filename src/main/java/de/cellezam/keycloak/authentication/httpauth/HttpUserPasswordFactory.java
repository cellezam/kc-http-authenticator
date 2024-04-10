package de.cellezam.keycloak.authentication.httpauth;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ServerInfoAwareProviderFactory;

import java.util.List;
import java.util.Map;

import static org.keycloak.models.AuthenticationExecutionModel.Requirement.*;

public final class HttpUserPasswordFactory implements AuthenticatorFactory, ServerInfoAwareProviderFactory {

    public static final String PROVIDER_ID = "user-password-delegation";

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = new AuthenticationExecutionModel.Requirement[]{AuthenticationExecutionModel.Requirement.REQUIRED, ALTERNATIVE};

    private Config.Scope config;

    public HttpUserPasswordFactory() {
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return new HttpUserPasswordAuthenticator();
    }
    @Override
    public void init(Config.Scope config) {
        this.config = config;
    }
    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }
    @Override
    public void close() {
    }
    @Override
    public String getId() {
        return PROVIDER_ID;
    }
    @Override
    public String getReferenceCategory() {
        return "password";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }
    @Override
    public String getDisplayType() {
        return "Username Password Custom Http Form";
    }
    @Override
    public String getHelpText() {
        return "Validates a username and password from login form via a custom http call";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return HttpUserPasswordConfigProperties.CONFIG_PROPERTIES;
    }
    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public Map<String, String> getOperationalInfo() {
        String version = getClass().getPackage().getImplementationVersion();
        if (version == null) {
            version = "dev-snapshot";
        }
        return Map.of("Version", version);
    }
}
