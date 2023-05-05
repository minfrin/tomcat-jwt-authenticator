/**
 * 
 */
package media.pepperpot.tca.authenticator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.crypto.SecretKey;

import org.apache.catalina.connector.Request;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

/**
 * @author minfrin
 *
 */
public class JwtAuthenticatorTest {

	/**
	 * Test a plain JWT as per https://tools.ietf.org/html/rfc7519#section-6.1
	 */
	@Test
	public void getPlainISSTest() {
		Request httpServletRequest = mock(Request.class);

		final Map<String, String> headers = new HashMap<String, String>();
		headers.put("Authorization",
				"Bearer eyJhbGciOiJub25lIn0" + "." + "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
						+ "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" + ".");

		Enumeration<String> headerNames = Collections.enumeration(headers.keySet());
		Enumeration<String> headerValues = Collections.enumeration(headers.values());

		when(httpServletRequest.getHeaderNames()).thenReturn(headerNames);
		when(httpServletRequest.getHeaders("Authorization")).thenReturn(headerValues);

		doAnswer(new Answer<String>() {
			@Override
			public String answer(InvocationOnMock invocation) throws Throwable {
				Object[] args = invocation.getArguments();
				return headers.get((String) args[0]);
			}
		}).when(httpServletRequest).getHeader("Authorization");

		assertNotNull(httpServletRequest.getHeader("Authorization"));

		Properties properties = new Properties();
		properties.setProperty(JwtAuthenticator.ALLOW_PLAIN, Boolean.TRUE.toString());

		String value = JwtAuthenticator.parseAuthorization(properties, httpServletRequest, "iss");

		assertEquals("joe", value);

	}

	/**
	 * Test a signed JWT as per https://tools.ietf.org/html/rfc7519#section-3.1
	 */
	@Test
	public void getSignedISSTest() {
		Request httpServletRequest = mock(Request.class);

		final Map<String, String> headers = new HashMap<String, String>();

		headers.put("Authorization",
				"Bearer eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" + "."
						+ "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
						+ "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" + "." + "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

		Enumeration<String> headerNames = Collections.enumeration(headers.keySet());
		Enumeration<String> headerValues = Collections.enumeration(headers.values());

		when(httpServletRequest.getHeaderNames()).thenReturn(headerNames);
		when(httpServletRequest.getHeaders("Authorization")).thenReturn(headerValues);

		doAnswer(new Answer<String>() {
			@Override
			public String answer(InvocationOnMock invocation) throws Throwable {
				Object[] args = invocation.getArguments();
				return headers.get((String) args[0]);
			}
		}).when(httpServletRequest).getHeader("Authorization");

		assertNotNull(httpServletRequest.getHeader("Authorization"));

		URL url = this.getClass().getResource("/rfc7515-a1.jwk");
		Properties properties = new Properties();
		properties.setProperty(JwtAuthenticator.JWS_ALGORITHM, "HS256");
		properties.setProperty(JwtAuthenticator.JWS_JWK_SET_URL, url.toString());
		properties.setProperty(JwtAuthenticator.JWT_MAX_CLOCK_SKEW, Integer.toString(Integer.MAX_VALUE));

		String value = JwtAuthenticator.parseAuthorization(properties, httpServletRequest, "iss");

		assertEquals("joe", value);

	}

	/**
	 * Test an encrypted JWT as per https://tools.ietf.org/html/rfc7519#appendix-A.1
	 */
	@Test
	public void getEncryptedISSTest() {
		Request httpServletRequest = mock(Request.class);

		final Map<String, String> headers = new HashMap<String, String>();

		headers.put("Authorization",
				"Bearer eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0."
						+ "QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iNqhWXaKH4MqAkQtM"
						+ "oNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLG"
						+ "TkND09XyjORj_CHAgOPJ-Sd8ONQRnJvWn_hXV1BNMHzUjPyYwEsRhDhzjAD26ima"
						+ "sOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52"
						+ "YCitxoQVPzjbl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a" + "1rZgN5TiysnmzTROF869lQ."
						+ "AxY8DCtDaGlsbGljb3RoZQ." + "MKOle7UQrG6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaM"
						+ "HDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8." + "fiK51VwhsxJ-siBMR-YFiA");

		Enumeration<String> headerNames = Collections.enumeration(headers.keySet());
		Enumeration<String> headerValues = Collections.enumeration(headers.values());

		when(httpServletRequest.getHeaderNames()).thenReturn(headerNames);
		when(httpServletRequest.getHeaders("Authorization")).thenReturn(headerValues);

		doAnswer(new Answer<String>() {
			@Override
			public String answer(InvocationOnMock invocation) throws Throwable {
				Object[] args = invocation.getArguments();
				return headers.get((String) args[0]);
			}
		}).when(httpServletRequest).getHeader("Authorization");

		assertNotNull(httpServletRequest.getHeader("Authorization"));

		URL url = this.getClass().getResource("/rfc7516-a2.jwk");
		Properties properties = new Properties();
		properties.setProperty(JwtAuthenticator.JWT_MAX_CLOCK_SKEW, Integer.toString(Integer.MAX_VALUE));
		properties.setProperty(JwtAuthenticator.JWE_JWK_SET_URL, url.toString());
		properties.setProperty(JwtAuthenticator.JWE_ALGORITHM, "RSA1_5");
		properties.setProperty(JwtAuthenticator.JWE_ENCRYPTION_METHOD, "A128CBC-HS256");

		String value = JwtAuthenticator.parseAuthorization(properties, httpServletRequest, "iss");

		assertEquals("joe", value);

	}

	/**
	 * Test a nested JWT as per https://tools.ietf.org/html/rfc7519#appendix-A.2
	 */
	@Test
	public void getNestedISSTest() {
		Request httpServletRequest = mock(Request.class);

		final Map<String, String> headers = new HashMap<String, String>();

		headers.put("Authorization",
				"Bearer eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiY3R5IjoiSldU" + "In0."
						+ "g_hEwksO1Ax8Qn7HoN-BVeBoa8FXe0kpyk_XdcSmxvcM5_P296JXXtoHISr_DD_M"
						+ "qewaQSH4dZOQHoUgKLeFly-9RI11TG-_Ge1bZFazBPwKC5lJ6OLANLMd0QSL4fYE"
						+ "b9ERe-epKYE3xb2jfY1AltHqBO-PM6j23Guj2yDKnFv6WO72tteVzm_2n17SBFvh"
						+ "DuR9a2nHTE67pe0XGBUS_TK7ecA-iVq5COeVdJR4U4VZGGlxRGPLRHvolVLEHx6D"
						+ "YyLpw30Ay9R6d68YCLi9FYTq3hIXPK_-dmPlOUlKvPr1GgJzRoeC9G5qCvdcHWsq" + "JGTO_z3Wfo5zsqwkxruxwA."
						+ "UmVkbW9uZCBXQSA5ODA1Mg." + "VwHERHPvCNcHHpTjkoigx3_ExK0Qc71RMEParpatm0X_qpg-w8kozSjfNIPPXiTB"
						+ "BLXR65CIPkFqz4l1Ae9w_uowKiwyi9acgVztAi-pSL8GQSXnaamh9kX1mdh3M_TT"
						+ "-FZGQFQsFhu0Z72gJKGdfGE-OE7hS1zuBD5oEUfk0Dmb0VzWEzpxxiSSBbBAzP10"
						+ "l56pPfAtrjEYw-7ygeMkwBl6Z_mLS6w6xUgKlvW6ULmkV-uLC4FUiyKECK4e3WZY"
						+ "Kw1bpgIqGYsw2v_grHjszJZ-_I5uM-9RA8ycX9KqPRp9gc6pXmoU_-27ATs9XCvr"
						+ "ZXUtK2902AUzqpeEUJYjWWxSNsS-r1TJ1I-FMJ4XyAiGrfmo9hQPcNBYxPz3GQb2"
						+ "8Y5CLSQfNgKSGt0A4isp1hBUXBHAndgtcslt7ZoQJaKe_nNJgNliWtWpJ_ebuOpE"
						+ "l8jdhehdccnRMIwAmU1n7SPkmhIl1HlSOpvcvDfhUN5wuqU955vOBvfkBOh5A11U"
						+ "zBuo2WlgZ6hYi9-e3w29bR0C2-pp3jbqxEDw3iWaf2dc5b-LnR0FEYXvI_tYk5rd"
						+ "_J9N0mg0tQ6RbpxNEMNoA9QWk5lgdPvbh9BaO195abQ." + "AVO9iT5AV4CzvDJCdhSFlQ");

		Enumeration<String> headerNames = Collections.enumeration(headers.keySet());
		Enumeration<String> headerValues = Collections.enumeration(headers.values());

		when(httpServletRequest.getHeaderNames()).thenReturn(headerNames);
		when(httpServletRequest.getHeaders("Authorization")).thenReturn(headerValues);

		doAnswer(new Answer<String>() {
			@Override
			public String answer(InvocationOnMock invocation) throws Throwable {
				Object[] args = invocation.getArguments();
				return headers.get((String) args[0]);
			}
		}).when(httpServletRequest).getHeader("Authorization");

		assertNotNull(httpServletRequest.getHeader("Authorization"));

		URL jwsUrl = this.getClass().getResource("/rfc7515-a2.jwk");
		URL jweUrl = this.getClass().getResource("/rfc7516-a2.jwk");
		Properties properties = new Properties();
		properties.setProperty(JwtAuthenticator.JWT_MAX_CLOCK_SKEW, Integer.toString(Integer.MAX_VALUE));
		properties.setProperty(JwtAuthenticator.JWS_JWK_SET_URL, jwsUrl.toString());
		properties.setProperty(JwtAuthenticator.JWS_ALGORITHM, "RS256");
		properties.setProperty(JwtAuthenticator.JWE_JWK_SET_URL, jweUrl.toString());
		properties.setProperty(JwtAuthenticator.JWE_ALGORITHM, "RSA1_5");
		properties.setProperty(JwtAuthenticator.JWE_ENCRYPTION_METHOD, "A128CBC-HS256");

		String value = JwtAuthenticator.parseAuthorization(properties, httpServletRequest, "iss");

		assertEquals("joe", value);

	}

	/**
	 * Test a plain JWT with a given subject.
	 * 
	 * @throws JOSEException
	 */
	@Test
	public void getPlainSubjectTest() throws JOSEException {
		Request httpServletRequest = mock(Request.class);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("alice").issuer("https://example.com")
				.expirationTime(new Date(new Date().getTime() + 60 * 1000)).build();

		PlainJWT plainJWT = new PlainJWT(claimsSet);

		final Map<String, String> headers = new HashMap<String, String>();
		headers.put("Authorization", "Bearer " + plainJWT.serialize());

		Enumeration<String> headerNames = Collections.enumeration(headers.keySet());
		Enumeration<String> headerValues = Collections.enumeration(headers.values());

		when(httpServletRequest.getHeaderNames()).thenReturn(headerNames);
		when(httpServletRequest.getHeaders("Authorization")).thenReturn(headerValues);

		doAnswer(new Answer<String>() {
			@Override
			public String answer(InvocationOnMock invocation) throws Throwable {
				Object[] args = invocation.getArguments();
				return headers.get((String) args[0]);
			}
		}).when(httpServletRequest).getHeader("Authorization");

		assertNotNull(httpServletRequest.getHeader("Authorization"));

		Properties properties = new Properties();
		properties.setProperty(JwtAuthenticator.ALLOW_PLAIN, Boolean.TRUE.toString());

		String value = JwtAuthenticator.parseAuthorization(properties, httpServletRequest, "sub");

		assertNotNull(value);
		assertEquals("alice", value);

	}

	/**
	 * Test a signed JWT with a given subject.
	 * 
	 * @throws JOSEException
	 * @throws ParseException
	 * @throws IOException
	 */
	@Test
	public void getSignedSubjectTest() throws JOSEException, IOException, ParseException {
		Request httpServletRequest = mock(Request.class);

		URL url = this.getClass().getResource("/rfc7515-a1.jwk");
		JWKSet jwkset = JWKSet.load(url.openStream());
		List<JWK> jwks = jwkset.getKeys();
		OctetSequenceKey key = OctetSequenceKey.class.cast(jwks.iterator().next());
		SecretKey secret = key.toSecretKey();

		JWSSigner signer = new MACSigner(secret.getEncoded());

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("alice").issuer("https://example.com")
				.expirationTime(new Date(new Date().getTime() + 60 * 1000)).build();

		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		signedJWT.sign(signer);

		final Map<String, String> headers = new HashMap<String, String>();
		headers.put("Authorization", "Bearer " + signedJWT.serialize());

		Enumeration<String> headerNames = Collections.enumeration(headers.keySet());
		Enumeration<String> headerValues = Collections.enumeration(headers.values());

		when(httpServletRequest.getHeaderNames()).thenReturn(headerNames);
		when(httpServletRequest.getHeaders("Authorization")).thenReturn(headerValues);

		doAnswer(new Answer<String>() {
			@Override
			public String answer(InvocationOnMock invocation) throws Throwable {
				Object[] args = invocation.getArguments();
				return headers.get((String) args[0]);
			}
		}).when(httpServletRequest).getHeader("Authorization");

		assertNotNull(httpServletRequest.getHeader("Authorization"));

		Properties properties = new Properties();
		properties.setProperty(JwtAuthenticator.JWS_ALGORITHM, "HS256");
		properties.setProperty(JwtAuthenticator.JWS_JWK_SET_URL, url.toString());
		properties.setProperty(JwtAuthenticator.JWT_MAX_CLOCK_SKEW, Integer.toString(Integer.MAX_VALUE));

		String value = JwtAuthenticator.parseAuthorization(properties, httpServletRequest, "sub");

		assertEquals("alice", value);

	}

}
