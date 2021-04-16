package com.bezkoder.springjwt.security.jwt;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequest;

import com.bezkoder.springjwt.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;

@Component
public class JwtUtils {
	private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

	@Value("${bezkoder.app.jwtSecret}")
	private String jwtSecret;

	@Value("${bezkoder.app.jwtExpirationMs}")
	private int jwtExpirationMs;

	public String generateJwtToken(Authentication authentication) {

		UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

		return Jwts.builder()
				.setSubject((userPrincipal.getUsername()))
				.setIssuedAt(new Date())
				.setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
				.signWith(SignatureAlgorithm.HS512, jwtSecret)
				.compact();
	}

	public String getUserNameFromJwtToken(String token) {
		return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
	}

	public boolean validateJwtToken(String authToken, HttpServletRequest httpServletRequest) {
                try {
                        Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
                        return true;
                } catch (SignatureException e) {
                //      log.error("Invalid JWT signature: {}", e.getMessage());
                        httpServletRequest.setAttribute("signature","Invalid Signature. Loggind out");
                } catch (MalformedJwtException e) {
                //      log.error("Invalid JWT token: {}", e.getMessage());
                        httpServletRequest.setAttribute("malformed","Invalid JWT token. Loggind out");
                } catch (ExpiredJwtException e) {
                //      log.error("JWT token is expired: {}", e.getMessage());
                        httpServletRequest.setAttribute("expired","Expired JWT token is expired. Login again.");
                } catch (UnsupportedJwtException e) {
                //      log.error("JWT token is unsupported: {}", e.getMessage());
                        httpServletRequest.setAttribute("unsupported","Unsupported JWT token. Logging out.");
                } catch (IllegalArgumentException e) {
                //      log.error("JWT claims string is empty: {}", e.getMessage());
                        httpServletRequest.setAttribute("illegalargument","JWT claims string is empty. Logging out");
                }

                return false;
        }

}
