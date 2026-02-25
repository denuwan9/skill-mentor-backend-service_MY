package com.stemlink.skillmentor.security;

import jakarta.annotation.Nonnull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class AuthenticationFilter extends OncePerRequestFilter {
    private final TokenValidator tokenValidator;

    @Override
    protected void doFilterInternal(@Nonnull HttpServletRequest request, @Nonnull HttpServletResponse response,
            @Nonnull FilterChain filterChain)
            throws ServletException, IOException {

        String token = extractToken(request);

        if (token != null) {
            System.out.println("DEBUG: Received token: " + token.substring(0, Math.min(token.length(), 20)) + "...");
            boolean isValid = tokenValidator.validateToken(token);
            System.out.println("DEBUG: Token validation result: " + isValid);
            if (isValid) {
                String userId = tokenValidator.extractUserId(token);
                String email = tokenValidator.extractEmail(token);
                String firstName = tokenValidator.extractFirstName(token);
                String lastName = tokenValidator.extractLastName(token);

                System.out.println("DEBUG: Extracted claims - userId: " + userId + ", email: " + email + ", name: "
                        + firstName + " " + lastName);

                UserPrincipal userPrincipal = new UserPrincipal(userId, email, firstName, lastName);

                List<String> roles = tokenValidator.extractRoles(token);
                List<GrantedAuthority> authorities = roles != null ? roles.stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                        .collect(Collectors.toList()) : new ArrayList<>();

                // Spring Security requires at least one granted authority to consider the user
                // fully authenticated
                // in some configurations, and to pass @PreAuthorize checks.
                if (authorities.isEmpty()) {
                    authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
                    authorities.add(new SimpleGrantedAuthority("ROLE_STUDENT"));
                }

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userPrincipal, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                System.out.println("DEBUG: Token is invalid according to tokenValidator.");
            }
        }

        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
