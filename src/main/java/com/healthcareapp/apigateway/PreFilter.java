package com.healthcareapp.apigateway;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.google.common.net.HttpHeaders;

import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class PreFilter implements GlobalFilter {
	
	@Autowired
	private Environment env;

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		ServerHttpRequest req = exchange.getRequest();
		log.info("Inside Pre filter {}, {}", req.getPath().toString());
		
		if((req.getPath().toString().contains("/user") && req.getMethodValue().contains("POST")) 
				|| (req.getPath().toString().contains("/login") && req.getMethodValue().contains("POST"))) {
			return chain.filter(exchange);
		}
		
		if(!req.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
			return onError(exchange, "No Authorization Header", HttpStatus.UNAUTHORIZED);
		}
		
		String authorizationHeader = req.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
		String jwt = authorizationHeader.replace("Bearer ", "");
		
		if(!isJwtValid(jwt)) {
			return onError(exchange, "Invalid JWT token", HttpStatus.UNAUTHORIZED);
		}
		
		return chain.filter(exchange);
	}
	
	private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus httpStatus) {
		ServerHttpResponse res = exchange.getResponse();
		res.setStatusCode(httpStatus);
		
		return res.setComplete();
	}
	
	private boolean isJwtValid(String jwt) {
		String subject = null;
		try{
			subject = Jwts.parser()
					.setSigningKey(env.getProperty("token.secret"))
					.parseClaimsJws(jwt)
					.getBody()
					.getSubject();
		}catch(Exception e) {
			return false;
		}
		
		return StringUtils.isNotEmpty(subject);
		
	}

}
