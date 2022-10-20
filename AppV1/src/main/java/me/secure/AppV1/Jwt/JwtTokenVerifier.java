package me.secure.AppV1.Jwt;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.google.common.base.Strings;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

public class JwtTokenVerifier extends OncePerRequestFilter {

	private final JwtConfig jwtConfig;
	private final SecretKey secretKey;

	public JwtTokenVerifier(JwtConfig jwtConfig, SecretKey secretkey) {
		this.jwtConfig = jwtConfig;
		this.secretKey = secretkey;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response,
			FilterChain filterChain)throws ServletException, IOException {

//		String authorizatonHeader = request.getHeader("Authorization");
		String authorizatonHeader = request.getHeader(jwtConfig.getAutherizationHeader());

		if(Strings.isNullOrEmpty(authorizatonHeader) ||
				!authorizatonHeader.startsWith(jwtConfig.getTokenPrefix())) {
			filterChain.doFilter(request, response);
			return;
		}

		String token = authorizatonHeader.replace(jwtConfig.getTokenPrefix(),"");
		try {
//			String secretkey = "securedKeySecuredBySecurityofSpringSecurity";

			Jws<Claims> claimsJws = Jwts.parser()
//					.setSigningKey(Keys.hmacShaKeyFor(secretkey.getBytes()))
					.setSigningKey(secretKey)
					.parseClaimsJws(token);

			Claims body = claimsJws.getBody();

			String username = body.getSubject();		//subject is User name e.g., Abi / Tom / Jack

			var authorities = (List<Map<String,String>>) body.get("authorities");

			Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
							.map(m -> new SimpleGrantedAuthority(m.get("authority")))
							.collect(Collectors.toSet());

			Authentication authentication = new UsernamePasswordAuthenticationToken(
					username, null , simpleGrantedAuthorities);

			//Setting authentication to be true
			SecurityContextHolder.getContext().setAuthentication(authentication);

		}catch (JwtException e) {
			throw new IllegalStateException(String.format("Token %s cannot be trusted",token));
		}

		//	request to be passed to next filter
		filterChain.doFilter(request, response);
	}
}
