package com.smartrecruitment.apigateway.security;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class JwtHeaderFilter implements GlobalFilter, Ordered {

    private final String internalServiceKey;
    private final ReactiveJwtDecoder jwtDecoder;

    public JwtHeaderFilter(String internalServiceKey, ReactiveJwtDecoder jwtDecoder) {
        this.internalServiceKey = internalServiceKey;
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public Mono<Void> filter (ServerWebExchange exchange,
                              org.springframework.cloud.gateway.filter.GatewayFilterChain chain
    ){

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }
        String token = authHeader.substring(7);

        return jwtDecoder.decode(token)
                .flatMap(jwt -> {
                    String userId = jwt.getSubject();
                    String role = jwt.getClaimAsString("role");


                    ServerHttpRequest mutatedRequest = exchange.getRequest()
                            .mutate()
                            .headers(headers -> {
                                headers.remove("X-User-Id");
                                headers.remove("X-User-Role");
                                headers.remove("X-INTERNAL-KEY");

                                headers.add("X-User-Id", userId);
                                if (role != null) headers.add("X-User-Role", role);
                                headers.add("X-INTERNAL-KEY", internalServiceKey);
                            })
                            .build();

                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                })
                .onErrorResume(e -> {
                    return chain.filter(exchange);
                });
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
