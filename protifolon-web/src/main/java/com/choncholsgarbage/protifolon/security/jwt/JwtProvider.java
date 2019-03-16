package com.choncholsgarbage.protifolon.security.jwt;


import com.choncholsgarbage.protifolon.security.services.UserPrinciple;
import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);

    @Value("${protifolon.app.jwtSecret}")
    private String jwtSecret;

    @Value("${protifolon.app.jwtExpiration}")
    private int jwtExpiration;

    public String generateJwtToken(Authentication authentication){

        UserPrinciple userPrinciple = (UserPrinciple) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject(userPrinciple.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpiration * 1000))
                .signWith(SignatureAlgorithm.ES512, jwtSecret)
                .compact();
    }

    public boolean validateJwtToken(String authToken){
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e){
            logger.error("Invalid JWT Signature. Message: { } ", e);
        } catch (MalformedJwtException e){
            logger.error("Invalid JWT token. Message: { } ", e);
        } catch (ExpiredJwtException e){
            logger.error("Expired JWT token. Message: { } ", e);
        } catch (UnsupportedJwtException e){
            logger.error("Unsupported JWT token. Message: { } ", e);
        } catch (IllegalArgumentException e){
            logger.error("JWT token is illegal. Message: { } ", e);
        }

        return false;
    }

    public String getUserNameFromJwtToken(String token){

        return Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}
