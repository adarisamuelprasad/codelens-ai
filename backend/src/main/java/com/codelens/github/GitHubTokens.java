package com.codelens.github;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Which token a review uses. With a GitHub App configured (app id + private
 * key), each installation gets a short-lived installation token, cached until
 * five minutes before it expires. Otherwise a static token if one is set
 * (handy for local runs), otherwise none: anonymous, public repos, 60
 * requests an hour.
 */
@Component
public class GitHubTokens {

    private record Cached(String token, Instant expiresAt) {}

    private final String appId;
    private final PrivateKey appKey;
    private final String staticToken;
    private final RestClient http;
    private final Clock clock;
    private final Map<Long, Cached> cache = new ConcurrentHashMap<>();

    @Autowired
    public GitHubTokens(@Value("${codelens.github.app-id:}") String appId,
                        @Value("${codelens.github.private-key:}") String privateKeyPem,
                        @Value("${codelens.github.token:}") String staticToken,
                        @Value("${codelens.github.api-url:https://api.github.com}") String apiUrl) {
        this(appId, privateKeyPem, staticToken, RestClient.builder().baseUrl(apiUrl)
            .defaultHeader("Accept", "application/vnd.github+json")
            .defaultHeader("User-Agent", "codelens-ai").build(), Clock.systemUTC());
    }

    GitHubTokens(String appId, String privateKeyPem, String staticToken, RestClient http, Clock clock) {
        this.appId = appId;
        this.appKey = privateKeyPem == null || privateKeyPem.isBlank() ? null : parsePrivateKey(privateKeyPem);
        this.staticToken = staticToken;
        this.http = http;
        this.clock = clock;
    }

    public boolean appConfigured() {
        return appKey != null && appId != null && !appId.isBlank();
    }

    /** The token for this installation, or the static token, or null. */
    public String forInstallation(Long installationId) {
        if (appConfigured() && installationId != null) {
            Cached c = cache.get(installationId);
            if (c != null && clock.instant().isBefore(c.expiresAt().minusSeconds(300))) return c.token();
            Map<?, ?> res = http.post().uri("/app/installations/{id}/access_tokens", installationId)
                .header("Authorization", "Bearer " + appJwt()).retrieve().body(Map.class);
            String token = (String) res.get("token");
            cache.put(installationId, new Cached(token, Instant.parse((String) res.get("expires_at"))));
            return token;
        }
        return staticToken == null || staticToken.isBlank() ? null : staticToken;
    }

    /** RS256 JWT identifying the App itself. GitHub accepts up to 10 minutes; 60 s back-dated for clock skew. */
    String appJwt() {
        long now = clock.instant().getEpochSecond();
        String header = b64("{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        String payload = b64("{\"iat\":" + (now - 60) + ",\"exp\":" + (now + 540) + ",\"iss\":\"" + appId + "\"}");
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(appKey);
            sig.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
            return header + "." + payload + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign());
        } catch (Exception e) {
            throw new IllegalStateException("Could not sign the GitHub App JWT", e);
        }
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * GitHub hands out App keys as PKCS#1 ("BEGIN RSA PRIVATE KEY"), which the
     * JDK cannot read directly; it is wrapped into PKCS#8 here. PKCS#8 keys
     * ("BEGIN PRIVATE KEY") are read as they are. Literal "\n" sequences are
     * accepted so the key can live in a one-line environment variable.
     */
    static PrivateKey parsePrivateKey(String pem) {
        String text = pem.replace("\\n", "\n");
        boolean pkcs1 = text.contains("BEGIN RSA PRIVATE KEY");
        String body = text.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);
        if (pkcs1) der = pkcs1ToPkcs8(der);
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalArgumentException("codelens.github.private-key is not a valid RSA private key", e);
        }
    }

    // PrivateKeyInfo ::= SEQUENCE { version 0, AlgorithmIdentifier rsaEncryption, OCTET STRING pkcs1 }
    private static final byte[] RSA_ALGORITHM_ID = {
        0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};

    static byte[] pkcs1ToPkcs8(byte[] pkcs1) {
        byte[] octet = derWrap((byte) 0x04, pkcs1);
        byte[] version = {0x02, 0x01, 0x00};
        byte[] inner = new byte[version.length + RSA_ALGORITHM_ID.length + octet.length];
        System.arraycopy(version, 0, inner, 0, version.length);
        System.arraycopy(RSA_ALGORITHM_ID, 0, inner, version.length, RSA_ALGORITHM_ID.length);
        System.arraycopy(octet, 0, inner, version.length + RSA_ALGORITHM_ID.length, octet.length);
        return derWrap((byte) 0x30, inner);
    }

    private static byte[] derWrap(byte tag, byte[] content) {
        int n = content.length;
        byte[] len;
        if (n < 0x80) len = new byte[] {(byte) n};
        else if (n < 0x100) len = new byte[] {(byte) 0x81, (byte) n};
        else if (n < 0x10000) len = new byte[] {(byte) 0x82, (byte) (n >> 8), (byte) n};
        else len = new byte[] {(byte) 0x83, (byte) (n >> 16), (byte) (n >> 8), (byte) n};
        byte[] out = new byte[1 + len.length + n];
        out[0] = tag;
        System.arraycopy(len, 0, out, 1, len.length);
        System.arraycopy(content, 0, out, 1 + len.length, n);
        return out;
    }
}
