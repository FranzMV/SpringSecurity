package com.spring_security.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.spring_security.constants.SecurityConstants;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtUtils {

    @Value("${spring.security.jwt.key.private}")
    private String privateKey;

    @Value("${spring.security.jwt.user.generator}")
    private String userGenerator;


    /**
     * Crea un JWT
     * @param authentication authentication
     * @return String Jwt
     */
    public String createToken(Authentication authentication){

        Algorithm algorithm = Algorithm.HMAC256(this.privateKey);

        String username = authentication.getPrincipal().toString();

        String authorities = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return JWT.create()
                .withIssuer(this.userGenerator)
                .withSubject(username)
                .withClaim(SecurityConstants.AUTHORITIES, authorities)
                .withIssuedAt(new Date())
                .withExpiresAt(new Date(System.currentTimeMillis() + 1800000))
                .withJWTId(UUID.randomUUID().toString())
                .withNotBefore(new Date(System.currentTimeMillis()))
                .sign(algorithm);
    }

    /**
     * Verifica el token
     * @param token token
     * @return JWTVerificationException e
     */
    public DecodedJWT validateToken(String token){
        try{
            Algorithm algorithm = Algorithm.HMAC256(this.privateKey);

            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(this.userGenerator)
                    .build();

            return verifier.verify(token);

        }catch (JWTVerificationException e){
            throw new JWTVerificationException("Invalid token, not Authorized");
        }
    }

    /**
     * Extrae el usuario del token
     * @param decodedJWT decodedJWT
     * @return decodedJWT.getSubject()
     */
    public String extractUsername(DecodedJWT decodedJWT){
        return decodedJWT.getSubject();
    }


    /**
     * Extrae un Claim expecifico del token a traves del nombre del Claim
     * @param decodedJWT decodedJWT
     * @param claimName claimName
     * @return Claim
     */
    public Claim getSpecificClaim(DecodedJWT decodedJWT, String claimName){
        return decodedJWT.getClaim(claimName);
    }

    /**
     * Devuelve todos los Claims
     * @param decodedJWT decodedJWT
     * @return Map<String, Claim> decodedJWT.getClaims()
     */
    public Map<String, Claim> returnAllClaims(DecodedJWT decodedJWT){
        return decodedJWT.getClaims();
    }
}
