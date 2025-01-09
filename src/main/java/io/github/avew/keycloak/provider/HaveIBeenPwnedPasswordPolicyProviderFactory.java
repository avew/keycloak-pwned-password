package io.github.avew.keycloak.provider;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;

public class HaveIBeenPwnedPasswordPolicyProviderFactory implements PasswordPolicyProviderFactory {
    public static final String PROVIDER_ID = "password-policy-have-i-been-pwned";

    @Override
    public String getDefaultConfigValue() {
        return "1";
    }

    @Override
    public String getConfigType() {
        return PasswordPolicyProvider.INT_CONFIG_TYPE;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayName() {
        return "Have I Been Pwned?";
    }

    @Override
    public PasswordPolicyProvider create(KeycloakSession session) {
        return new HaveIBeenPwnedPasswordPolicyProvider(
                new PasswordService(),
                new HaveIBeenPwnedApiService(),
                session.getContext()
        );
    }

    @Override
    public void init(Config.Scope config) {
        // Initialization code here
    }

    @Override
    public boolean isMultiplSupported() {
        return false;
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Post-initialization code here
    }

    @Override
    public void close() {
        // Cleanup code here
    }
}
