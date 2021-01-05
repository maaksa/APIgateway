package sk_microservices.APIgateway.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;

import static sk_microservices.APIgateway.security.SecurityConstants.*;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    public JwtAuthenticationFilter() {

    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {

        String token = req.getHeader(HEADER_STRING);

        UsernamePasswordAuthenticationToken authentication = null;
        authentication = getAuthentication(req, token);
        if(authentication != null) {
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(req, res);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request, String token) {

        if (token != null) {
            DecodedJWT jwt = JWT.require(Algorithm.HMAC512(SECRET.getBytes())).build()
                    .verify(token.replace(TOKEN_PREFIX, ""));

            String email = jwt.getSubject();

            if (email != null) {
                return new UsernamePasswordAuthenticationToken(email, null, new ArrayList<>());
            }
        }
        return null;
    }

}
