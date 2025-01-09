package io.github.avew.keycloak.provider;

import org.keycloak.models.KeycloakContext;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PolicyError;

import java.util.Optional;

public class HaveIBeenPwnedPasswordPolicyProvider implements PasswordPolicyProvider {
    private final PasswordService passwordService;
    private final HaveIBeenPwnedApiService pwnedService;
    private final KeycloakContext context;

    public HaveIBeenPwnedPasswordPolicyProvider(PasswordService passwordService, HaveIBeenPwnedApiService pwnedService, KeycloakContext context) {
        this.passwordService = passwordService;
        this.pwnedService = pwnedService;
        this.context = context;
    }

    @Override
    public PolicyError validate(String username, String password) {
        int passwordPwnThreshold = context.getRealm().getPasswordPolicy().getPolicyConfig(HaveIBeenPwnedPasswordPolicyProviderFactory.PROVIDER_ID);
        String passwordHash = passwordService.hash(password);

        try {
            Optional<PwnedPassword> pwned = pwnedService.lookupPwnedPasswordsByHash(passwordHash)
                    .stream()
                    .filter(p -> pwnedService.hashMatchesPwnedPassword(passwordHash, p))
                    .findFirst();

            if (!pwned.isPresent()) {
                return null;
            }

            if (pwned.get().getPwnCount() < passwordPwnThreshold) {
                return null;
            }

            String formattedPwnCount = String.format("%,d", pwned.get().getPwnCount());
            return new PolicyError("Please choose a different password. According to Have I Been Pwned, this password appears " +
                    formattedPwnCount + " times across a number of data breaches. For more information, visit https://haveibeenpwned.com");
        } catch (HaveIBeenPwnedApiException e) {
            // Handle exception, perhaps logging it or rethrowing as a runtime exception
            e.printStackTrace();
            return new PolicyError("Error checking password safety.");
        }
    }

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        return validate(user.getUsername(), password);
    }


    @Override
    public Object parseConfig(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return 1; // Default threshold if parsing fails
        }
    }

    @Override
    public void close() {
        // Resource cleanup if necessary
    }
}