package com.api.gateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayConfig {

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route(r -> r.path("/service1/**")
                        .uri("http://localhost:8081"))  // Route to service 1
                .route(r -> r.path("/service2/**")
                        .uri("http://localhost:8082"))  // Route to service 2
                .build();
    }
}
