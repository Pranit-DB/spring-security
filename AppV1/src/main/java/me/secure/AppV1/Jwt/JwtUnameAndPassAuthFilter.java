package me.secure.AppV1.Jwt;

import java.io.IOException;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.security.Keys;

public class JwtUnameAndPassAuthFilter extends UsernamePasswordAuthenticationFilter{

	private final AuthenticationManager authManager;

	private final JwtConfig jwtConfig;
	private final SecretKey secretKey;

	public JwtUnameAndPassAuthFilter(AuthenticationManager authManager,
			JwtConfig jwtConfig,
			SecretKey secretKey) {

		this.authManager = authManager;
		this.jwtConfig = jwtConfig;
		this.secretKey = secretKey;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request,
												HttpServletResponse response)
												throws AuthenticationException {
		try {
			UnameAndPassAuthRequest authRequest = new ObjectMapper()
					.readValue(request.getInputStream(),UnameAndPassAuthRequest.class);

			Authentication authentication = new UsernamePasswordAuthenticationToken(
					authRequest.getUsername(),
					authRequest.getPassword()
					);
// Below line will make sure that user name exists with correct password before authentication
			Authentication authenticate = authManager.authenticate(authentication);
			return authenticate;

		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	//On successful authentication below method will take place
	//Sending token for use of subsequent requests
	@Override
	protected void successfulAuthentication(HttpServletRequest request,
			HttpServletResponse response,
			FilterChain chain,
			Authentication authResult) throws IOException, ServletException {

		String token = Jwts.builder()
				.setSubject(authResult.getName())	//Abi / Tom / Jack in this case
				.claim("authorities", authResult.getAuthorities())	//Claim & Body kind of same
				.setIssuedAt(new Date())
				.setExpiration(java.sql.Date.valueOf(java.time.LocalDate.now().plusWeeks(2)))
//				.signWith(Keys.hmacShaKeyFor(key.getBytes()))
				.signWith(secretKey)
				.compact();

//		response.addHeader("Authorization","Bearer "+ token);
		response.addHeader(jwtConfig.getAutherizationHeader(),jwtConfig.getTokenPrefix()+ token);
	}
}
