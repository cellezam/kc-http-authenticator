package de.cellezam.keycloak.authentication.httpauth;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.regex.Pattern;

final class HttpUserPasswordAuthenticator extends AbstractUsernameFormAuthenticator implements Authenticator {

    protected static ServicesLogger log;

    private static final String EMAIL_PATTERN = "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$";


    public HttpUserPasswordAuthenticator() {
    }

    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String username = context.getHttpRequest().getDecodedFormParameters().getFirst("username");

        if (formData.containsKey("cancel")) {
            context.cancelLogin();
        } else if (this.validateForm(context, formData)) {
            UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);
            if (user == null) {
                //TODO Maybe we could populate the user object with the return of the api.
                user = context.getSession().users().addUser(context.getRealm(), username);
                user.setEnabled(true); // Optionally enable the user
                user.setEmailVerified(true);
                user.setEmail(username);
                user.setUsername(username);
                user.setFirstName(username);
                user.setLastName(username);
            }
            context.setUser(user);
            context.success();
        }
    }

    public static boolean isValidEmail(String email) {
        Pattern pattern = Pattern.compile(EMAIL_PATTERN);
        return pattern.matcher(email).matches();
    }

    private int makeExternalServerCall(String username, String password, HttpUserPasswordConfig config) {
        log.info(config.baseURL());
        log.info(username);
        log.info(password);
        log.info("will make the http call");
        try {
            // URL and payload
            String url = config.baseURL(); //"https://boapi-score-uat.oneytrust.com/authentication_token";
            String payload = "{\"username\": \"" + username + "\", \"password\": \"" + password + "\"}";

            // Create URL object
            URL obj = new URL(url);

            // Create HttpURLConnection instance
            HttpURLConnection con = (HttpURLConnection) obj.openConnection();

            // Set request method
            con.setRequestMethod("POST");

            // Set request headers
            con.setRequestProperty("Content-Type", "application/json");

            // Enable input and output streams
            con.setDoOutput(true);
            con.setDoInput(true);

            // Send POST request
            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.writeBytes(payload);
            wr.flush();
            wr.close();

            // Get response code
            int responseCode = con.getResponseCode();
            System.out.println("Response Code : " + responseCode);

            // Read response
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            // Print response
            System.out.println("Response: " + response.toString());
            return responseCode;
        } catch (Exception e) {
            e.printStackTrace();
            return 400;
        }
    }

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        HttpUserPasswordAuthenticationFlowContext httpUserPasswordAuthenticationFlowContext = new HttpUserPasswordAuthenticationFlowContext(context);

        String username = context.getHttpRequest().getDecodedFormParameters().getFirst("username");
        String password = context.getHttpRequest().getDecodedFormParameters().getFirst("password");

        if (!isValidEmail(username)) {
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
                context.form().setError(Messages.INVALID_USER)
                    .setError(Messages.INVALID_USER)
                    .createErrorPage(Response.Status.UNAUTHORIZED));
            return false;
        }
        HttpUserPasswordConfig config = httpUserPasswordAuthenticationFlowContext.config();

        // Make HTTP call to external server
        int statusCode = makeExternalServerCall(username, password, config);
        int configStatusCode = Integer.parseInt(config.successStatusCode());

        if (statusCode == configStatusCode) {
            return true;
        }
        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS,
            context.form().setError(Messages.INVALID_USER)
                .setError(Messages.INVALID_USER)
                .createErrorPage(Response.Status.UNAUTHORIZED));
        return false;
    }

    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = new MultivaluedHashMap();
        String loginHint = context.getAuthenticationSession().getClientNote("login_hint");
        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getSession());
        if (context.getUser() != null) {
            LoginFormsProvider form = context.form();
            form.setAttribute("usernameHidden", true);
            form.setAttribute("registrationDisabled", true);
            context.getAuthenticationSession().setAuthNote("USER_SET_BEFORE_USERNAME_PASSWORD_AUTH", "true");
        } else {
            context.getAuthenticationSession().removeAuthNote("USER_SET_BEFORE_USERNAME_PASSWORD_AUTH");
            if (loginHint != null || rememberMeUsername != null) {
                if (loginHint != null) {
                    formData.add("username", loginHint);
                } else {
                    formData.add("username", rememberMeUsername);
                    formData.add("rememberMe", "on");
                }
            }
        }

        Response challengeResponse = this.challenge(context, formData);
        context.challenge(challengeResponse);
    }

    public boolean requiresUser() {
        return false;
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();
        if (formData.size() > 0) {
            forms.setFormData(formData);
        }

        return forms.createLoginUsernamePassword();
    }

    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    public void close() {
    }

    static {
        log = ServicesLogger.LOGGER;
    }
}
