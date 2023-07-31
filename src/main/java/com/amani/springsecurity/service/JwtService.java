package com.amani.springsecurity.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
    private static final String SECRET_KEY = "f64A9XDC5t38G7GVeee4NolDyIOlLaTKmj+RxGsB3fLfpKn4T5MkNZRErul57tbeeOCnlMrkgi5SegEYkYpUGQWyyuE3IwY6H+Q7ClJ1NzG4hPSRbQPnAW59aRlDE4B23cp9J+BsZoPexwWyYeTtEHbHDIjGbu614bdWwwRgbuBvl8G5dAMQRjQI7PQAkN82VpSJKu/64H0e50fJSOdLbYfD2laZ/ZnNXh3pW4wbvPHife2bT8sxz7FS+MhGfc5vuOy4q+Bs7aQbVECEzHCdM14HQPsGL9HprU+oGLUNSgjgY2A2fW3kzoloHrozknTtAVttA27lWEa/eeHXPFEI0U4/jywifW/YICSzINHa6TE=";;

    public String extractUsername(String token) {
        return extractAllClaim(token, Claims::getSubject);
    }

    public <T> T extractAllClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);

    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();

    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExipired(token);

    }

    private boolean isTokenExipired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractAllClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
