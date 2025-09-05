package com.ecommerce.user.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")  // من properties, غيره في الإنتاج
    private String SECRET;
    public String generatesToken(String userName) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", "ecommerce");  // issuer
        claims.put("aud", "users");    // audience
        return createToken(claims, userName);
    }

    public String createToken(Map<String, Object> claims, String userName) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(userName)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30)) // 30 minutes
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuer("ecommerce")         // ← هنا
                .setAudience("users")           // ← هنا
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 7)) // 7 أيام
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .requireIssuer("ecommerce")  // أضف تحقق issuer
                .requireAudience("users")  // أضف تحقق audience
                .setAllowedClockSkewSeconds(60)  // للتعامل مع clock skew
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    public Date extractExpiration(String token){
        return extractClaim(token,Claims::getExpiration);
    }

    public Boolean isTokenExpired (String token ){
return extractExpiration(token).before(new Date()) ;
    }
    public Boolean validateToken (String token , UserDetails userDetails){
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
