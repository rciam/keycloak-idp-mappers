package org.keycloak.broker.provider;

import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.List;

public class PosixUsernameMapper extends AbstractIdentityProviderMapper {

    public static final String[] COMPATIBLE_PROVIDERS = {
            IdentityProviderMapper.ANY_PROVIDER
    };

    public static final String PROVIDER_ID = "posix-username-mapper";

    // Config property keys
    private static final String PROP_TARGET_ATTRIBUTE = "targetAttribute";
    private static final String PROP_MAX_LENGTH       = "maxLength";
    private static final String PROP_PREFIX           = "prefix";
    private static final String PROP_SUFFIX           = "suffix";

    private static final int DEFAULT_MAX_LENGTH = 10;
    private static final int UPPER_MAX_LENGTH   = 24;

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty targetAttribute = new ProviderConfigProperty();
        targetAttribute.setName(PROP_TARGET_ATTRIBUTE);
        targetAttribute.setLabel("Target Attribute Name");
        targetAttribute.setHelpText("The user attribute that will store the generated POSIX-compliant username.");
        targetAttribute.setType(ProviderConfigProperty.STRING_TYPE);
        targetAttribute.setRequired(true);
        CONFIG_PROPERTIES.add(targetAttribute);

        ProviderConfigProperty maxLength = new ProviderConfigProperty();
        maxLength.setName(PROP_MAX_LENGTH);
        maxLength.setLabel("Maximum Length");
        maxLength.setHelpText("Maximum length of the generated value (default: 10, max: 24).");
        maxLength.setType(ProviderConfigProperty.STRING_TYPE); // stored as string in Keycloak config
        maxLength.setDefaultValue(String.valueOf(DEFAULT_MAX_LENGTH));
        CONFIG_PROPERTIES.add(maxLength);

        ProviderConfigProperty prefix = new ProviderConfigProperty();
        prefix.setName(PROP_PREFIX);
        prefix.setLabel("Prefix");
        prefix.setHelpText("Optional prefix prepended to the generated value (will be lowercased and stripped to [a-z0-9]).");
        prefix.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(prefix);

        ProviderConfigProperty suffix = new ProviderConfigProperty();
        suffix.setName(PROP_SUFFIX);
        suffix.setLabel("Suffix");
        suffix.setHelpText("Optional suffix appended to the generated value (will be lowercased and stripped to [a-z0-9]).");
        suffix.setType(ProviderConfigProperty.STRING_TYPE);
        CONFIG_PROPERTIES.add(suffix);
    }

    // -------------------------------------------------------------------------
    // SPI identity
    // -------------------------------------------------------------------------

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayCategory() {
        return "POSIX Username Generator";
    }

    @Override
    public String getDisplayType() {
        return "POSIX Username Generator";
    }

    @Override
    public String getHelpText() {
        return "Generates a unique, POSIX-compliant attribute value (e.g. Linux username) "
                + "derived from the user's firstName, lastName, and Keycloak username.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    /**
     * Accept every IdP type — return an empty array so the wildcard match applies.
     */
    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    // -------------------------------------------------------------------------
    // Mapper lifecycle hooks
    // -------------------------------------------------------------------------

    /** Called during the first-login / broker flow, before the user is persisted. */
    @Override
    public void preprocessFederatedIdentity(KeycloakSession session,
                                            RealmModel realm,
                                            IdentityProviderMapperModel mapperModel,
                                            BrokeredIdentityContext context) {
        var targetAttr = mapperModel.getConfig().get(PROP_TARGET_ATTRIBUTE);
        if (targetAttr == null || targetAttr.isBlank()) return;

        var generated = generateAndReserve(session, realm, mapperModel, context, null);
        context.setUserAttribute(targetAttr, generated);
    }

    /** Called on subsequent logins to keep the attribute up-to-date. */
    @Override
    public void updateBrokeredUser(KeycloakSession session,
                                   RealmModel realm,
                                   UserModel user,
                                   IdentityProviderMapperModel mapperModel,
                                   BrokeredIdentityContext context) {
        String targetAttr = mapperModel.getConfig().get(PROP_TARGET_ATTRIBUTE);
        if (targetAttr == null || targetAttr.isBlank()) return;

        // Only regenerate if the attribute is not yet set
        if (user.getFirstAttribute(targetAttr) != null) return;

        String generated = generateAndReserve(session, realm, mapperModel, context, user);
        user.setSingleAttribute(targetAttr, generated);
    }

    // -------------------------------------------------------------------------
    // Core generation logic
    // -------------------------------------------------------------------------

    private String generateAndReserve(KeycloakSession session,
                                      RealmModel realm,
                                      IdentityProviderMapperModel mapperModel,
                                      BrokeredIdentityContext context,
                                      UserModel existingUser) {

        int maxLen = parseMaxLength(mapperModel.getConfig().get(PROP_MAX_LENGTH));

        String rawPrefix = sanitize(mapperModel.getConfig().getOrDefault(PROP_PREFIX, ""));
        String rawSuffix = sanitize(mapperModel.getConfig().getOrDefault(PROP_SUFFIX, ""));
        String targetAttr = mapperModel.getConfig().get(PROP_TARGET_ATTRIBUTE);

        // --- name part ---
        String firstName = nullToEmpty(context.getFirstName());
        String lastName  = nullToEmpty(context.getLastName());

        String n   = sanitize(firstName.isEmpty() ? "x" : String.valueOf(firstName.charAt(0)));
        String lll = sanitize(lastName.length() >= 3 ? lastName.substring(0, 3) : lastName);
        if (lll.isEmpty()) lll = "x"; // ultimate fallback

        // --- hash part ---
        String username = nullToEmpty(context.getUsername());
        String hhhh = sha256Hex4(username.isEmpty() ? n + lll : username);

        // Build the raw base (without prefix/suffix)
        String core = n + lll + hhhh; // e.g. "jdoe3f2a"

        // Assemble with prefix/suffix, then enforce maxLen and POSIX first-char rule
        String base = buildBase(rawPrefix, core, rawSuffix, maxLen);
        base = ensureStartsWithLetter(base);

        // --- collision resolution ---
        String candidate = base;
        int counter = 2;
        while (hasCollision(session, realm, targetAttr, candidate, existingUser)) {
            String counterStr = String.valueOf(counter);
            // Truncate base to leave room for the counter digits
            int allowedBaseLen = maxLen - counterStr.length();
            if (allowedBaseLen < 1) {
                // Extreme edge-case: maxLen is tiny; just use counter alone (with a letter prefix)
                candidate = "u" + counterStr.substring(0, Math.min(counterStr.length(), maxLen - 1));
            } else {
                candidate = base.substring(0, Math.min(base.length(), allowedBaseLen)) + counterStr;
            }
            counter++;
        }

        return candidate;
    }

    /**
     * Assembles prefix + core + suffix and trims to maxLen.
     * The trimming priority is: protect prefix and suffix first; shorten core in the middle.
     */
    private String buildBase(String prefix, String core, String suffix, int maxLen) {
        int available = maxLen - prefix.length() - suffix.length();
        if (available <= 0) {
            // prefix + suffix already exceed maxLen — truncate suffix, then prefix
            String combined = (prefix + suffix).substring(0, maxLen);
            return combined;
        }
        String trimmedCore = core.substring(0, Math.min(core.length(), available));
        return prefix + trimmedCore + suffix;
    }

    // -------------------------------------------------------------------------
    // POSIX sanitization helpers
    // -------------------------------------------------------------------------

    /**
     * Transliterates to ASCII, lowercases, and strips any character outside [a-z0-9].
     */
    private static String sanitize(String input) {
        if (input == null || input.isEmpty()) return "";
        // NFD decomposition → drop combining marks → ASCII lowercase
        var normalized = Normalizer.normalize(input, Normalizer.Form.NFD)
                .replaceAll("\\p{M}", "");
        return normalized.toLowerCase().replaceAll("[^a-z0-9]", "");
    }

    /**
     * Ensures the string starts with [a-z]. If the first character is a digit,
     * prepend 'u' and trim the last character to stay within maxLen — but here
     * we just prepend; the caller already enforces maxLen via buildBase / trimming.
     */
    private static String ensureStartsWithLetter(String s) {
        if (s.isEmpty()) return "u";
        if (Character.isLetter(s.charAt(0))) return s;
        return "u" + s; // will be trimmed by the caller if needed
    }

    // -------------------------------------------------------------------------
    // SHA-256 helpers
    // -------------------------------------------------------------------------

    private static String sha256Hex4(String input) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            var hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            var hex = new StringBuilder();
            for (var b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.substring(0, 4);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed by the JVM spec — should never happen
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    // -------------------------------------------------------------------------
    // Collision detection
    // -------------------------------------------------------------------------

    private boolean hasCollision(KeycloakSession session,
                                 RealmModel realm,
                                 String attributeName,
                                 String value,
                                 UserModel excludeUser) {
        var matches = session.users()
                .searchForUserByUserAttributeStream(realm, attributeName, value);

        if (excludeUser == null) {
            return matches.findAny().isPresent();
        }

        final String excludeId = excludeUser.getId();
        return matches.anyMatch(u -> !u.getId().equals(excludeId));
    }

    // -------------------------------------------------------------------------
    // Misc helpers
    // -------------------------------------------------------------------------

    private static int parseMaxLength(String raw) {
        if (raw == null || raw.isBlank()) return DEFAULT_MAX_LENGTH;
        try {
            int v = Integer.parseInt(raw.trim());
            if (v < 1)                return DEFAULT_MAX_LENGTH;
            if (v > UPPER_MAX_LENGTH) return UPPER_MAX_LENGTH;
            return v;
        } catch (NumberFormatException e) {
            return DEFAULT_MAX_LENGTH;
        }
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s.trim();
    }
}
