package com.codelens.github;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

import com.codelens.web.WebhookController;

class GitHubTokensTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-30T10:00:00Z"), ZoneOffset.UTC);

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
            + "\n-----END " + type + "-----\n";
    }

    /** The PKCS#1 body inside a PKCS#8 key: what GitHub's "BEGIN RSA PRIVATE KEY" file holds. */
    private static byte[] pkcs1Of(byte[] pkcs8) {
        // PKCS#8 = SEQUENCE { INTEGER 0, AlgorithmIdentifier(15 bytes), OCTET STRING { pkcs1 } }
        int i = 1 + lengthBytes(pkcs8, 1) + 3 + 15;   // skip outer header, version, algorithm id
        int len = lengthAt(pkcs8, i + 1);
        int start = i + 1 + lengthBytes(pkcs8, i + 1);
        return Arrays.copyOfRange(pkcs8, start, start + len);
    }

    private static int lengthBytes(byte[] d, int at) {
        return (d[at] & 0x80) == 0 ? 1 : 1 + (d[at] & 0x7f);
    }

    private static int lengthAt(byte[] d, int at) {
        if ((d[at] & 0x80) == 0) return d[at];
        int n = 0;
        for (int k = 1; k <= (d[at] & 0x7f); k++) n = (n << 8) | (d[at + k] & 0xff);
        return n;
    }

    @Test
    void readsGitHubsPkcs1KeyAndSignsAVerifiableJwt() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String githubStyle = pem("RSA PRIVATE KEY", pkcs1Of(kp.getPrivate().getEncoded()));
        GitHubTokens t = new GitHubTokens("12345", githubStyle, "", RestClient.create(), CLOCK);
        assertTrue(t.appConfigured());

        String[] jwt = t.appJwt().split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(jwt[1]), StandardCharsets.UTF_8);
        assertTrue(payload.contains("\"iss\":\"12345\""), payload);
        long now = CLOCK.instant().getEpochSecond();
        assertTrue(payload.contains("\"iat\":" + (now - 60)) && payload.contains("\"exp\":" + (now + 540)), payload);

        Signature verify = Signature.getInstance("SHA256withRSA");
        verify.initVerify(kp.getPublic());
        verify.update((jwt[0] + "." + jwt[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(verify.verify(Base64.getUrlDecoder().decode(jwt[2])));
    }

    @Test
    void readsPkcs8AndOneLineEnvironmentVariableForm() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String oneLine = pem("PRIVATE KEY", kp.getPrivate().getEncoded()).replace("\n", "\\n");
        assertEquals(kp.getPrivate(), GitHubTokens.parsePrivateKey(oneLine));
    }

    @Test
    void rejectsGarbageKeys() {
        assertThrows(IllegalArgumentException.class,
            () -> GitHubTokens.parsePrivateKey("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"));
    }

    @Test
    void withoutAnAppFallsBackToStaticTokenThenAnonymous() {
        assertEquals("pat", new GitHubTokens("", "", "pat", RestClient.create(), CLOCK).forInstallation(42L));
        GitHubTokens none = new GitHubTokens("", "", "", RestClient.create(), CLOCK);
        assertFalse(none.appConfigured());
        assertNull(none.forInstallation(42L));
    }

    @Test
    void webhookSignatureCheck() throws Exception {
        byte[] secret = "s3cret".getBytes(StandardCharsets.UTF_8);
        byte[] body = "{\"a\":1}".getBytes(StandardCharsets.UTF_8);
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256"));
        String good = "sha256=" + java.util.HexFormat.of().formatHex(mac.doFinal(body));
        assertTrue(WebhookControllerAccess.valid(secret, body, good));
        assertFalse(WebhookControllerAccess.valid(secret, "{\"a\":2}".getBytes(), good), "body changed");
        assertFalse(WebhookControllerAccess.valid(secret, body, null));
        assertFalse(WebhookControllerAccess.valid(secret, body, "sha1=abc"));
        assertFalse(WebhookControllerAccess.valid(secret, body, "sha256=not-hex"));
    }

    static final class WebhookControllerAccess {
        static boolean valid(byte[] s, byte[] b, String h) {
            try {
                var m = WebhookController.class.getDeclaredMethod("validSignature", byte[].class, byte[].class, String.class);
                m.setAccessible(true);
                return (boolean) m.invoke(null, s, b, h);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
