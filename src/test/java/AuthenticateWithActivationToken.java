import com.okta.sdk.clients.AuthApiClient;
import com.okta.sdk.clients.UserApiClient;
import com.okta.sdk.framework.ApiClientConfiguration;
import com.okta.sdk.models.auth.AuthResult;
import com.okta.sdk.models.users.ActivationResponse;
import com.okta.sdk.models.users.LoginCredentials;
import com.okta.sdk.models.users.Password;
import com.okta.sdk.models.users.User;
import com.okta.sdk.models.users.UserProfile;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * Created by vagrant on 4/9/17.
 */
public class AuthenticateWithActivationToken {

    UserApiClient userApiClient;
    AuthApiClient authApiClient;

    @BeforeClass
    public void setup() throws Exception {
        Map customHeaders = new HashMap();
        TestConfig.MockOkta testConfig = Util.parseTestConfig().getMockOkta();
        testConfig.setApiKey("00SCiaKALN5romaCAq_sChA7iYCjPSZYota8L-MTYc");
        testConfig.setPort(1802);
        testConfig.setProxy("http://rain.okta1.com");

        ApiClientConfiguration cfg = new ApiClientConfiguration(
                        String.format("%s:%d", testConfig.getProxy(), testConfig.getPort()),
                        testConfig.getApiKey(),
                        customHeaders);
        userApiClient = new UserApiClient(cfg);
        authApiClient = new AuthApiClient(cfg);
    }

    @Test
    public void createAndActivateUser() throws IOException {
        String userId = null;
        try {
            String name = "u6";
            String login = name + "@t.com";
            User user = userApiClient.createUser(name, name, login, login, false);
            assertNotNull(user.getId());
            assertEquals(user.getStatus(), "STAGED");
            userId = user.getId();

            Map activation = userApiClient.activateUser(user.getId());
            assertNotNull(activation.get("activationToken"));
            assertNotNull(activation.get("activationUrl"));
            ActivationResponse activationResponse = new ActivationResponse();
            activationResponse.setActivationToken(activation.get("activationToken").toString());
            activationResponse.setActivationUrl(activation.get("activationUrl").toString());

            User result = userApiClient.getUser(user.getId());
            assertEquals(result.getStatus(), "PROVISIONED");

            AuthResult authResult = authApiClient.authenticateWithActivationToken(activationResponse.getActivationToken());
            assertEquals(authResult.getStatus(), "PASSWORD_RESET");
            assertNotNull(authResult.getStateToken());

            authResult = authApiClient.resetPassword(authResult.getStateToken(), "", "New0Password$$%");
            assertNotNull(authResult.getSessionToken());
            assertEquals(authResult.getStatus(), "SUCCESS");
        }
        finally {
            if (userId != null) {
                userApiClient.deactivateUser(userId);
                userApiClient.deleteUser(userId);
            }
        }
    }

    @Test
    public void createAndActivateUserWithCredentials() throws IOException {
        String userId = null;
        try {
            String name = "z6";
            String login = name + "@t.com";

            UserProfile userProfile = new UserProfile();
            userProfile.setFirstName(name);
            userProfile.setLastName(name);
            userProfile.setLogin(login);
            userProfile.setEmail(login);

            LoginCredentials credentials = new LoginCredentials();
            Password p = new Password();
            p.setValue("New0Password$$%");
            credentials.setPassword(p);

            User user = new User();
            user.setProfile(userProfile);
            user.setCredentials(credentials);

            user = userApiClient.createUser(user, false);
            assertNotNull(user.getId());
            assertEquals(user.getStatus(), "STAGED");
            userId = user.getId();

            Map activation = userApiClient.activateUser(user.getId());
            assertNotNull(activation.get("activationToken"));
            assertNotNull(activation.get("activationUrl"));
            ActivationResponse activationResponse = new ActivationResponse();
            activationResponse.setActivationToken(activation.get("activationToken").toString());
            activationResponse.setActivationUrl(activation.get("activationUrl").toString());

            User result = userApiClient.getUser(user.getId());
            assertEquals(result.getStatus(), "ACTIVE");

            AuthResult authResult = authApiClient.authenticateWithActivationToken(activationResponse.getActivationToken());
            assertNotNull(authResult.getSessionToken());
            assertEquals(authResult.getStatus(), "SUCCESS");
        }
        finally {
            if (userId != null) {
                userApiClient.deactivateUser(userId);
                userApiClient.deleteUser(userId);
            }
        }
    }
}
