package com.smartrecruitment.apigateway;

import com.smartrecruitment.apigateway.security.JwtHeaderFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

@SpringBootApplication
@EnableDiscoveryClient
public class ApiGatewayApplication {
    @Value("${internal.service.key}")
    private String internalServiceKey;

    public static void main(String[] args) {
        SpringApplication.run(ApiGatewayApplication.class, args);
    }

    @Bean
    public JwtHeaderFilter jwtHeaderFilter(ReactiveJwtDecoder jwtDecoder) {
        System.out.println(">>> internal.service.key in Gateway = [" + internalServiceKey + "]");
        return new JwtHeaderFilter(internalServiceKey, jwtDecoder);
    }
}
