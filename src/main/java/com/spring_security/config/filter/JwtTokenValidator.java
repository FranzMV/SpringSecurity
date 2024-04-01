package com.spring_security.config.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.spring_security.constants.SecurityConstants;
import com.spring_security.utils.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;

public class JwtTokenValidator extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;

    /**
     * Constructor
     * @param jwtUtils jwtUtils
     */
    public JwtTokenValidator(JwtUtils jwtUtils){this.jwtUtils = jwtUtils;}

    /**
     * Valida el token
     * @param request request
     * @param response response
     * @param filterChain filterChain
     * @throws ServletException ServletException
     * @throws IOException IOException
     */
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        String jwtToken = request.getHeader(HttpHeaders.AUTHORIZATION);

        if(jwtToken != null){
            //Quitamos la palabra Bearer y el espacio del token (Bearer 1aaklsdjalsdiq12390asdjl;asd)
            jwtToken = jwtToken.substring(7);
            //Valida el token
            DecodedJWT decodedJWT = jwtUtils.validateToken(jwtToken);
            //Obtiene el username
            String username = jwtUtils.extractUsername(decodedJWT);
            //obtiene los permisos del usuario
            String stringAuthorities = jwtUtils.getSpecificClaim(decodedJWT, SecurityConstants.AUTHORITIES).asString();
            //Obtiene los permisos separados por coma
            Collection<? extends GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(stringAuthorities);

            SecurityContext context = SecurityContextHolder.getContext();
            Authentication authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
        }
        filterChain.doFilter(request, response);
    }
}
