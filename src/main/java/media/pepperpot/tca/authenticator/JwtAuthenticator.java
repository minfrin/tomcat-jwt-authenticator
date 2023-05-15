package media.pepperpot.tca.authenticator;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Principal;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.connector.Request;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/**
 * If a JWT Bearer token is included with the request, validate the token and return the token subject as the principal.
 *
 * @author minfrin
 *
 * @version $Id: $Id
 */
public class JwtAuthenticator extends AuthenticatorBase {

    private final static Log log = LogFactory.getLog(JwtAuthenticator.class);

    /** Constant <code>BEARER="BEARER"</code> */
    public static final String BEARER = "BEARER";

    /** Constant <code>ALLOW_PLAIN="media.pepperpot.jwt.allowPlain"</code> */
    public static final String ALLOW_PLAIN = "media.pepperpot.jwt.allowPlain";
    /** Constant <code>DEFAULT_ALLOW_PLAIN="Boolean.FALSE.toString()"</code> */
    public static final String DEFAULT_ALLOW_PLAIN = Boolean.FALSE.toString();
    /** Constant <code>JWS_SECRET_FILE="media.pepperpot.jws.SecretFile"</code> */
    public static final String JWS_SECRET_FILE = "media.pepperpot.jws.SecretFile";
    /** Constant <code>JWS_JWK_SET_FILE="media.pepperpot.jws.JwkSetFile"</code> */
    public static final String JWS_JWK_SET_FILE = "media.pepperpot.jws.JwkSetFile";
    /** Constant <code>JWS_REMOTE_JWK_SET_URL="media.pepperpot.jws.RemoteJwkSetUrl"</code> */
    public static final String JWS_REMOTE_JWK_SET_URL = "media.pepperpot.jws.RemoteJwkSetUrl";
    /** Constant <code>JWS_ALGORITHM="media.pepperpot.jwt.JWSAlgorithm"</code> */
    public static final String JWS_ALGORITHM = "media.pepperpot.jwt.JWSAlgorithm";
    /** Constant <code>JWE_SECRET_FILE="media.pepperpot.jwe.SecretFile"</code> */
    public static final String JWE_SECRET_FILE = "media.pepperpot.jwe.SecretFile";
    /** Constant <code>JWE_JWK_SET_FILE="media.pepperpot.jwe.JwkSetFile"</code> */
    public static final String JWE_JWK_SET_FILE = "media.pepperpot.jwe.JwkSetFile";
    /** Constant <code>JWE_REMOTE_JWK_SET_URL="media.pepperpot.jwe.RemoteJwkSetUrl"</code> */
    public static final String JWE_REMOTE_JWK_SET_URL = "media.pepperpot.jwe.RemoteJwkSetUrl";
    /** Constant <code>JWE_ALGORITHM="media.pepperpot.jwt.JWEAlgorithm"</code> */
    public static final String JWE_ALGORITHM = "media.pepperpot.jwt.JWEAlgorithm";
    /** Constant <code>JWE_ENCRYPTION_METHOD="media.pepperpot.jwt.JWEEncryptionMethod"</code> */
    public static final String JWE_ENCRYPTION_METHOD = "media.pepperpot.jwt.JWEEncryptionMethod";
    /** Constant <code>JWT_MAX_CLOCK_SKEW="media.pepperpot.jwt.MaxClockSkew"</code> */
    public static final String JWT_MAX_CLOCK_SKEW = "media.pepperpot.jwt.MaxClockSkew";
    /** Constant <code>JWT_MAX_CLOCK_SKEW_DEFAULT="60"</code> */
    public static final String JWT_MAX_CLOCK_SKEW_DEFAULT = "60";
    /** Constant <code>JWT_ACCEPTED_AUDIENCE="media.pepperpot.jwt.AcceptedAudience"</code> */
    public static final String JWT_ACCEPTED_AUDIENCE = "media.pepperpot.jwt.AcceptedAudience";
    /** Constant <code>JWT_REQUIRED_CLAIMS="media.pepperpot.jwt.RequiredClaims"</code> */
    public static final String JWT_REQUIRED_CLAIMS = "media.pepperpot.jwt.RequiredClaims";
    /** Constant <code>JWT_PROHIBITED_CLAIMS="media.pepperpot.jwt.ProhibitedClaims"</code> */
    public static final String JWT_PROHIBITED_CLAIMS = "media.pepperpot.jwt.ProhibitedClaims";

    protected Properties properties = null;

    /**
     * <p>
     * Constructor for JwtAuthenticator.
     * </p>
     */
    public JwtAuthenticator() {
        super();
        properties = System.getProperties();
    }

    /**
     * <p>
     * Constructor for JwtAuthenticator.
     * </p>
     *
     * @param properties
     *            a {@link java.util.Properties} object.
     */
    public JwtAuthenticator(Properties properties) {
        super();
        this.properties = properties;
    }

    /**
     * Parse the Authorization header, and extract the sub from the first valid JWT found.
     *
     * @param request
     *            a {@link org.apache.catalina.connector.Request} object.
     * @param properties
     *            a {@link java.util.Properties} object.
     * @param claimName
     *            a {@link java.lang.String} object.
     *
     * @return a {@link java.lang.String} object.
     */
    protected static String parseAuthorization(Properties properties, Request request, String claimName) {

        Enumeration<String> authorizations = request.getHeaders("Authorization");
        if (authorizations == null || !authorizations.hasMoreElements()) {
            if (log.isFatalEnabled()) {
                log.fatal("No Authorization header found in request: request=" + request + ", remoteHost="
                        + request.getRemoteHost() + ", remoteIP=" + request.getRemoteAddr());
            }
            return null;
        }

        List<String> statuses = new ArrayList<String>();

        while (authorizations.hasMoreElements()) {
            String authorization = authorizations.nextElement();

            String[] split = authorization.split(" ", 2);
            if (split == null || split.length != 2 || !"Bearer".equals(split[0])) {
                statuses.add("Authorization header found, but not a Bearer token");
                continue;
            }
            String jwt = split[1];

            if (jwt == null) {
                statuses.add("No JWT token found in Bearer Authentication header");
                continue;
            }

            try {

                String jwsSecretFile = properties.getProperty(JWS_SECRET_FILE);
                String jwsJwkSetFile = properties.getProperty(JWS_JWK_SET_FILE);
                String jwsRemoteJwkSetUrl = properties.getProperty(JWS_REMOTE_JWK_SET_URL);

                String jweSecretFile = properties.getProperty(JWE_SECRET_FILE);
                String jweJwkSetFile = properties.getProperty(JWE_JWK_SET_FILE);
                String jweRemoteJwkSetUrl = properties.getProperty(JWE_REMOTE_JWK_SET_URL);

                JWT parsed = JWTParser.parse(jwt);

                JWTClaimsSet claims = null;

                if (parsed instanceof PlainJWT) {

                    String allow = properties.getProperty(ALLOW_PLAIN, DEFAULT_ALLOW_PLAIN);
                    if (!Boolean.TRUE.toString().equals(allow)) {
                        statuses.add(
                                "Plain JWT tokens are not allowed by parameter -D'\" + ALLOW_PLAIN + \"', ignoring");
                        continue;
                    }

                    claims = parsed.getJWTClaimsSet();

                } else if (parsed instanceof SignedJWT) {

                    ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<SecurityContext>();

                    JWKSource<SecurityContext> keySource = null;

                    if (!isBlank(jwsSecretFile)) {
                        byte[] secret;
                        try {
                            secret = Files.readAllBytes(Paths.get(jwsSecretFile));
                        } catch (IOException e) {
                            statuses.add("JWT token is signed, but secret '" + jwsSecretFile + "' could not be read: "
                                    + e.toString());
                            continue;
                        }
                        keySource = new ImmutableSecret<SecurityContext>(secret);
                    } else if (!isBlank(jwsJwkSetFile)) {
                        try {
                            keySource = new ImmutableJWKSet<SecurityContext>(JWKSet.load(new File(jwsJwkSetFile)));
                        } catch (IOException e) {
                            statuses.add("JWT token is signed, but remote JWK set '" + jwsJwkSetFile
                                    + "' could not be read: " + e.toString());
                            continue;
                        }
                    } else if (!isBlank(jwsRemoteJwkSetUrl)) {
                        try {
                            keySource = JWKSourceBuilder.<SecurityContext> create(new URL(jwsRemoteJwkSetUrl)).build();
                        } catch (MalformedURLException e) {
                            statuses.add("JWT token is signed, but remote JWK set '" + jwsRemoteJwkSetUrl
                                    + "' was a malformed URL: " + e.toString());
                            continue;
                        }
                    } else {
                        statuses.add(
                                "JWT token is signed, but we have no secret or remote jwk set to verify it against");
                        continue;
                    }

                    String jwsAlgorithmString = properties.getProperty(JWS_ALGORITHM);
                    JWSAlgorithm expectedJWSAlg = JWSAlgorithm.parse(jwsAlgorithmString);
                    if (expectedJWSAlg == null) {
                        statuses.add(
                                "JWT token is signed, but JWS algorithm was not recognised: " + jwsAlgorithmString);
                        continue;
                    }

                    JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<SecurityContext>(
                            expectedJWSAlg, keySource);
                    jwtProcessor.setJWSKeySelector(keySelector);

                    String jwtMaxClockSkewString = properties.getProperty(JWT_MAX_CLOCK_SKEW,
                            JWT_MAX_CLOCK_SKEW_DEFAULT);
                    String jwtAcceptedAudienceString = properties.getProperty(JWT_ACCEPTED_AUDIENCE);
                    String jwtRequiredClaimsString = properties.getProperty(JWT_REQUIRED_CLAIMS);
                    String jwtProhibitedClaimsString = properties.getProperty(JWT_PROHIBITED_CLAIMS);
                    try {
                        Set<String> jwtAcceptedAudience = jwtAcceptedAudienceString == null ? null
                                : Arrays.stream(jwtAcceptedAudienceString.split(",")).map(String::trim)
                                        .collect(Collectors.toSet());
                        Set<String> jwtRequiredClaims = jwtRequiredClaimsString == null ? null
                                : Arrays.stream(jwtRequiredClaimsString.split(",")).map(String::trim)
                                        .collect(Collectors.toSet());
                        Set<String> jwtProhibitedClaims = jwtProhibitedClaimsString == null ? null
                                : Arrays.stream(jwtProhibitedClaimsString.split(",")).map(String::trim)
                                        .collect(Collectors.toSet());
                        DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier = new DefaultJWTClaimsVerifier<SecurityContext>(
                                jwtAcceptedAudience, null, jwtRequiredClaims, jwtProhibitedClaims);
                        claimsVerifier.setMaxClockSkew(Integer.parseInt(jwtMaxClockSkewString));
                        jwtProcessor.setJWTClaimsSetVerifier(claimsVerifier);
                    } catch (NumberFormatException e) {
                        statuses.add("JWT token is signed, but " + JWT_MAX_CLOCK_SKEW + " could not be parsed: "
                                + jwsAlgorithmString + " :" + e.toString());
                        continue;
                    }

                    SecurityContext ctx = null;

                    try {
                        claims = jwtProcessor.process(parsed, ctx);
                    } catch (BadJOSEException e) {
                        statuses.add("JWT token was signed, but was formatted badly: " + e.toString());
                        continue;
                    } catch (JOSEException e) {
                        statuses.add("JWT token was signed, but was could not be verified: " + e.toString());
                        continue;
                    }

                } else if (parsed instanceof EncryptedJWT) {

                    ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<SecurityContext>();

                    JWKSource<SecurityContext> keySource = null;

                    /* use the jwsSecretFile as encryption secret, unless overridden below */
                    if (!isBlank(jwsSecretFile)) {
                        byte[] secret;
                        try {
                            secret = Files.readAllBytes(Paths.get(jwsSecretFile));
                        } catch (IOException e) {
                            statuses.add("JWT token is encrypted, but signature secret '" + jwsSecretFile
                                    + "' could not be read: " + e.toString());
                            continue;
                        }
                        keySource = new ImmutableSecret<SecurityContext>(secret);
                    } else if (!isBlank(jwsJwkSetFile)) {
                        try {
                            keySource = new ImmutableJWKSet<SecurityContext>(JWKSet.load(new File(jwsJwkSetFile)));
                        } catch (IOException e) {
                            statuses.add("JWT token is encrypted, but signature remote JWK set '" + jwsJwkSetFile
                                    + "' could not be read: " + e.toString());
                            continue;
                        }
                    } else if (!isBlank(jwsRemoteJwkSetUrl)) {
                        try {
                            keySource = JWKSourceBuilder.<SecurityContext> create(new URL(jwsRemoteJwkSetUrl)).build();
                        } catch (MalformedURLException e) {
                            statuses.add("JWT token is encrypted, but signature remote JWK set '" + jwsRemoteJwkSetUrl
                                    + "' could not be read: " + e.toString());
                            continue;
                        }
                    }

                    JWSAlgorithm expectedJWSAlg = null;
                    String jwsAlgorithmString = properties.getProperty(JWS_ALGORITHM);
                    if (!isBlank(jwsAlgorithmString)) {
                        expectedJWSAlg = JWSAlgorithm.parse(jwsAlgorithmString);
                        if (expectedJWSAlg == null) {
                            statuses.add("JWT token is encrypted, but signature JWS algorithm was not recognised: "
                                    + jwsAlgorithmString);
                            continue;
                        }
                    }

                    if (expectedJWSAlg != null && keySource == null) {
                        statuses.add("JWT token is encrypted and signature JWS algorithm was set to '"
                                + jwsAlgorithmString + "', but none of '" + JWS_SECRET_FILE + "', '" + JWS_JWK_SET_FILE
                                + "', or '" + JWS_REMOTE_JWK_SET_URL + "' is set");
                        continue;
                    }

                    if (expectedJWSAlg != null) {
                        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<SecurityContext>(
                                expectedJWSAlg, keySource);
                        jwtProcessor.setJWSKeySelector(keySelector);
                    }

                    if (!isBlank(jweSecretFile)) {
                        byte[] secret;
                        try {
                            secret = Files.readAllBytes(Paths.get(jweSecretFile));
                        } catch (IOException e) {
                            statuses.add("JWT token is encrypted, but encryption secret '" + jweSecretFile
                                    + "' could not be read: " + e.toString());
                            continue;
                        }
                        keySource = new ImmutableSecret<SecurityContext>(secret);
                    } else if (!isBlank(jweJwkSetFile)) {
                        try {
                            keySource = new ImmutableJWKSet<SecurityContext>(JWKSet.load(new File(jweJwkSetFile)));
                        } catch (IOException e) {
                            statuses.add("JWT token is encrypted, but encryption remote JWK set '" + jweJwkSetFile
                                    + "' could not be read: " + e.toString());
                            continue;
                        }
                    } else if (!isBlank(jweRemoteJwkSetUrl)) {
                        try {
                            keySource = JWKSourceBuilder.<SecurityContext> create(new URL(jweRemoteJwkSetUrl)).build();
                        } catch (MalformedURLException e) {
                            statuses.add("JWT token is encrypted, but encryption remote JWK set '" + jweRemoteJwkSetUrl
                                    + "' could not be read: " + e.toString());
                            continue;
                        }
                    } else {
                        statuses.add("JWT token is encrypted, but we have no '" + JWE_SECRET_FILE + "'. '"
                                + JWE_JWK_SET_FILE + "' or '" + JWE_REMOTE_JWK_SET_URL + "' to verify it against");
                        continue;
                    }

                    JWEAlgorithm expectedJWEAlg = null;
                    String jweAlgorithmString = properties.getProperty(JWE_ALGORITHM);
                    if (!isBlank(jweAlgorithmString)) {
                        expectedJWEAlg = JWEAlgorithm.parse(jweAlgorithmString);
                        if (expectedJWEAlg == null) {
                            statuses.add("JWT token is encrypted, but JWE algorithm was not recognised: "
                                    + jweAlgorithmString);
                            continue;
                        }
                    } else {
                        statuses.add(
                                "JWT token is encrypted, but JWE algorithm '" + JWE_ALGORITHM + "' was not specified");
                        continue;
                    }

                    EncryptionMethod expectedJWEEnc = null;
                    String jweEncryptedMethodString = properties.getProperty(JWE_ENCRYPTION_METHOD);
                    if (!isBlank(jweEncryptedMethodString)) {
                        expectedJWEEnc = EncryptionMethod.parse(jweEncryptedMethodString);
                        if (expectedJWEEnc == null) {
                            statuses.add("JWT token is encrypted, but JWE encryption method was not recognised: "
                                    + jweEncryptedMethodString);
                            continue;
                        }
                    } else {
                        statuses.add("JWT token is encrypted, but JWE encryption method '" + JWE_ENCRYPTION_METHOD
                                + "' was not specified");
                        continue;
                    }

                    JWEKeySelector<SecurityContext> jweKeySelector = new JWEDecryptionKeySelector<SecurityContext>(
                            expectedJWEAlg, expectedJWEEnc, keySource);
                    jwtProcessor.setJWEKeySelector(jweKeySelector);

                    String jwtMaxClockSkewString = properties.getProperty(JWT_MAX_CLOCK_SKEW,
                            JWT_MAX_CLOCK_SKEW_DEFAULT);
                    String jwtAcceptedAudienceString = properties.getProperty(JWT_ACCEPTED_AUDIENCE);
                    String jwtRequiredClaimsString = properties.getProperty(JWT_REQUIRED_CLAIMS);
                    String jwtProhibitedClaimsString = properties.getProperty(JWT_PROHIBITED_CLAIMS);
                    try {
                        Set<String> jwtAcceptedAudience = jwtAcceptedAudienceString == null ? null
                                : Arrays.stream(jwtAcceptedAudienceString.split(",")).map(String::trim)
                                        .collect(Collectors.toSet());
                        Set<String> jwtRequiredClaims = jwtRequiredClaimsString == null ? null
                                : Arrays.stream(jwtRequiredClaimsString.split(",")).map(String::trim)
                                        .collect(Collectors.toSet());
                        Set<String> jwtProhibitedClaims = jwtProhibitedClaimsString == null ? null
                                : Arrays.stream(jwtProhibitedClaimsString.split(",")).map(String::trim)
                                        .collect(Collectors.toSet());
                        DefaultJWTClaimsVerifier<SecurityContext> claimsVerifier = new DefaultJWTClaimsVerifier<SecurityContext>(
                                jwtAcceptedAudience, null, jwtRequiredClaims, jwtProhibitedClaims);
                        claimsVerifier.setMaxClockSkew(Integer.parseInt(jwtMaxClockSkewString));
                        jwtProcessor.setJWTClaimsSetVerifier(claimsVerifier);
                    } catch (NumberFormatException e) {
                        statuses.add("JWT token is signed, but " + JWT_MAX_CLOCK_SKEW + " could not be parsed: "
                                + jwsAlgorithmString + " :" + e.toString());
                        continue;
                    }

                    SecurityContext ctx = null;

                    try {
                        claims = jwtProcessor.process(parsed, ctx);
                    } catch (BadJOSEException e) {
                        statuses.add("JWT token was signed, but was formatted badly: " + e.toString());
                        continue;
                    } catch (JOSEException e) {
                        statuses.add("JWT token was signed, but was could not be verified: " + e.toString());
                        continue;
                    }

                } else {
                    statuses.add("JWT token is neither plain, signed, not encrypted");
                    continue;
                }

                if (claims == null) {
                    statuses.add("JWT token found, but claims were missing");
                    continue;
                }

                final String claim = claims.getStringClaim(claimName);

                if (claim == null) {
                    statuses.add("JWT token found, but claim '" + claimName + "' was missing");
                    continue;
                }

                if (log.isInfoEnabled()) {
                    log.info("JWT token accepted with " + claimName + " '" + claim + "': request=" + request
                            + ", remoteHost=" + request.getRemoteHost() + ", remoteIP=" + request.getRemoteAddr());
                }

                return claim;

            } catch (ParseException e) {
                statuses.add("JWT token found but could not be parsed: " + e.toString());
            }

        }

        /* log out accumulated statuses */
        for (String status : statuses) {
            if (log.isFatalEnabled()) {
                log.fatal(status + ": request=" + request + ", remoteHost=" + request.getRemoteHost() + ", remoteIP="
                        + request.getRemoteAddr());
            }
        }

        return null;

    }

    /** {@inheritDoc} */
    @Override
    protected String getAuthMethod() {
        return BEARER;
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doAuthenticate(Request request, HttpServletResponse response) throws IOException {

        if (checkForCachedAuthentication(request, response, false)) {
            return true;
        }

        if (log.isInfoEnabled()) {
            log.info("...attempting to process JWT token in request: request=" + request + ", remoteHost="
                    + request.getRemoteHost() + ", remoteIP=" + request.getRemoteAddr());
        }

        final String sub = parseAuthorization(properties, request, "sub");

        if (sub != null) {

            Principal principal = context.getRealm().authenticate(sub);
            if (principal != null) {
                register(request, response, principal, BEARER, sub, null);

                return true;
            }

        }

        return false;

    }

    private static boolean isBlank(String str) {
        int strLen;
        if (str == null || (strLen = str.length()) == 0) {
            return true;
        }
        for (int i = 0; i < strLen; i++) {
            if ((Character.isWhitespace(str.charAt(i)) == false)) {
                return false;
            }
        }
        return true;
    }

}
