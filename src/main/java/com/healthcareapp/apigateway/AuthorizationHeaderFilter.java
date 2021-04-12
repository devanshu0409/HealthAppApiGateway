package com.healthcareapp.apigateway;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.google.common.net.HttpHeaders;

import io.jsonwebtoken.Jwts;
import reactor.core.publisher.Mono;

@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {
	
	@Autowired
	private Environment env;
	
	public AuthorizationHeaderFilter() {
		super(Config.class);
	}
	
	public static class Config {
		// Put COnfig properties here
	}
	
	@Override
	public GatewayFilter apply(Config config) {
		return (exchange, chain) -> {
			ServerHttpRequest req = exchange.getRequest();
			if(!req.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
				return onError(exchange, "No Authorization Header", HttpStatus.UNAUTHORIZED);
			}
			
			String authorizationHeader = req.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
			String jwt = authorizationHeader.replace("Bearer ", "");
			
			if(!isJwtValid(jwt)) {
				return onError(exchange, "Invalid JWT token", HttpStatus.UNAUTHORIZED);
			}
			
			return chain.filter(exchange);
		};
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