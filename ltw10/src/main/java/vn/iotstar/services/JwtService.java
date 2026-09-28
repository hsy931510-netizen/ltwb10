package vn.iotstar.services;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time}")
    private long jwtExpiration;

    /**
     * Trích xuất username (email) từ Nimbus SignedJWT token
     */
    public String extractUsername(String token) {
        return extractClaim(token, JWTClaimsSet::getSubject);
    }

    /**
     * Trích xuất claim bất kỳ từ JWTClaimsSet bằng claimsResolver
     */
    public <T> T extractClaim(String token, Function<JWTClaimsSet, T> claimsResolver) {
        final JWTClaimsSet claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Tạo token mặc định từ UserDetails
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Tạo token với claim bổ sung và thời gian hết hạn đọc từ application.properties
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    /**
     * Lấy cấu hình thời gian hết hạn của token (ms)
     */
    public long getExpirationTime() {
        return jwtExpiration;
    }

    /**
     * Xây dựng và ký SignedJWT bằng thư viện Nimbus JOSE + JWT
     */
    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expiration
    ) {
        try {
            // 1. Tạo JWS Header với thuật toán HMAC-SHA256
            JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);

            // 2. Tạo JWT Claims Set
            Date now = new Date(System.currentTimeMillis());
            Date exp = new Date(now.getTime() + expiration);

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .subject(userDetails.getUsername())
                    .issueTime(now)
                    .expirationTime(exp);

            if (extraClaims != null) {
                extraClaims.forEach(claimsBuilder::claim);
            }

            JWTClaimsSet claimsSet = claimsBuilder.build();

            // 3. Khởi tạo SignedJWT và ký với MACSigner
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            JWSSigner signer = new MACSigner(getSigningKeyBytes());
            signedJWT.sign(signer);

            // 4. Serialize sang chuỗi Compact JWT
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Lỗi khi tạo JWT token bằng Nimbus: " + e.getMessage(), e);
        }
    }

    /**
     * Kiểm tra tính hợp lệ của token (chữ ký hợp lệ, đúng username và chưa hết hạn)
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);

            // Xác thực chữ ký bằng MACVerifier
            JWSVerifier verifier = new MACVerifier(getSigningKeyBytes());
            if (!signedJWT.verify(verifier)) {
                return false;
            }

            final String username = extractUsername(token);
            return username != null && username.equals(userDetails.getUsername()) && !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Kiểm tra token đã hết hạn chưa
     */
    private boolean isTokenExpired(String token) {
        Date expiration = extractExpiration(token);
        return expiration != null && expiration.before(new Date());
    }

    /**
     * Trích xuất thời gian hết hạn từ token
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, JWTClaimsSet::getExpirationTime);
    }

    /**
     * Phân tích và trích xuất JWTClaimsSet từ token
     */
    private JWTClaimsSet extractAllClaims(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new BadCredentialsException("Định dạng token JWT không hợp lệ hoặc đã bị thay đổi: " + e.getMessage(), e);
        }
    }

    /**
     * Giải mã chuỗi secretKey sang byte array cho MACSigner / MACVerifier
     */
    private byte[] getSigningKeyBytes() {
        try {
            byte[] decoded = Base64.getDecoder().decode(secretKey);
            if (decoded.length >= 32) {
                return decoded;
            }
        } catch (Exception ignored) {
        }
        return secretKey.getBytes(StandardCharsets.UTF_8);
    }
}
