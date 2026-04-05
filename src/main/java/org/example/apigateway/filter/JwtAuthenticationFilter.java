package org.example.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

/**
 * Global JWT authentication filter.
 *
 * <p>Behavior:
 * <ul>
 *   <li>No Authorization header → pass through (downstream service handles access control)</li>
 *   <li>Invalid / expired token → 401 Unauthorized immediately</li>
 *   <li>Valid token → extract claims, inject X-User-Id, X-User-Roles, X-User-Email headers</li>
 * </ul>
 *
 * <p>Downstream services trust these headers and set up their SecurityContext from them
 * (see GatewayHeaderFilter in ContentService).
 */
@Slf4j
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");

        // No token provided — pass through, downstream service decides if auth is required
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }

        String token = authHeader.substring(7);

        try {
            SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));

            Claims claims = Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // Extract claims from JWT
            Object userIdRaw = claims.get("user_id");
            String role      = claims.get("role", String.class);
            String email     = claims.get("email", String.class);
            String firstName = claims.get("firstname", String.class);
            String lastName  = claims.get("lastname", String.class);

            // Build mutated request with downstream headers
            ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate();

            if (userIdRaw != null) {
                requestBuilder.header("X-User-Id", userIdRaw.toString());
            }
            if (role != null) {
                // Spring Security's hasRole('USER') expects authority "ROLE_USER"
                requestBuilder.header("X-User-Roles", "ROLE_" + role);
            }
            if (email != null) {
                requestBuilder.header("X-User-Email", email);
            }
            if (firstName != null) {
                requestBuilder.header("X-User-Firstname", firstName);
            }
            if (lastName != null) {
                requestBuilder.header("X-User-Lastname", lastName);
            }

            log.debug("JWT validated for user_id={}, role={}", userIdRaw, role);

            return chain.filter(exchange.mutate().request(requestBuilder.build()).build());

        } catch (JwtException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    @Override
    public int getOrder() {
        return -1; // Run before all other filters
    }
}
