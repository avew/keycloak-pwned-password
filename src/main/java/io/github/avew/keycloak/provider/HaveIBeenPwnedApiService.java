package io.github.avew.keycloak.provider;

import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class HaveIBeenPwnedApiService {

    private static final String SERVICE_URI = "https://api.pwnedpasswords.com";
    private final OkHttpClient client = new OkHttpClient();

    public List<PwnedPassword> lookupPwnedPasswordsByHash(String hash) throws HaveIBeenPwnedApiException {
        String hashPrefix = hash.substring(0, 5);
        HttpUrl url = HttpUrl.parse(SERVICE_URI).newBuilder()
                .addPathSegment("range")
                .addPathSegment(hashPrefix)
                .build();

        Request request = new Request.Builder()
                .url(url)
                .addHeader("User-Agent", "keycloak-password-policy-have-i-been-pwned")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new HaveIBeenPwnedApiException("Non-200 response from " + url + ". Status code: " + response.code() + ". Body: " + Objects.requireNonNull(response.body()).string());
            }

            String responseBody = Objects.requireNonNull(response.body()).string();
            List<PwnedPassword> pwnedPasswords = new ArrayList<>();
            String[] lines = responseBody.split("\n");
            for (String line : lines) {
                String[] parts = line.trim().split(":");
                pwnedPasswords.add(new PwnedPassword(parts[0], Integer.parseInt(parts[1])));
            }
            return pwnedPasswords;
        } catch (IOException e) {
            throw new HaveIBeenPwnedApiException("Failed to fetch data: " + e.getMessage());
        }
    }

    public boolean hashMatchesPwnedPassword(String hash, PwnedPassword pwnedPassword) {
        String hashSuffix = hash.substring(5);
        return hashSuffix.equalsIgnoreCase(pwnedPassword.getHashSuffix());
    }

}

