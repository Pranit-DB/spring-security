package me.secure.AppV1.Security;

import javax.crypto.SecretKey;

//import static me.secure.AppV1.Security.AppUserRole.*;

//import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//during jwt import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
//during jwt import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import me.secure.AppV1.Jwt.JwtConfig;
import me.secure.AppV1.Jwt.JwtTokenVerifier;
import me.secure.AppV1.Jwt.JwtUnameAndPassAuthFilter;
import me.secure.AppV1.Service.AppUserService;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AppSecurityConfig extends WebSecurityConfigurerAdapter {

	private final PasswordEncoder passwordEncoder;
	private final AppUserService appUserService;

	private final JwtConfig jwtConfig;
	private final SecretKey secretkey;

	@Autowired
	public AppSecurityConfig(PasswordEncoder passwordEncoder,AppUserService appUserService,
			JwtConfig jwtConfig,SecretKey secretkey) {
		this.passwordEncoder = passwordEncoder;
		this.appUserService = appUserService;
		this.jwtConfig = jwtConfig;
		this.secretkey = secretkey;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
	http
		.csrf()
//		.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//		.and()
		.disable()		//Cross side request forgery token disabled
		.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and()
		.addFilter(new JwtUnameAndPassAuthFilter(authenticationManager(), jwtConfig, secretkey))
		.addFilterAfter(new JwtTokenVerifier(jwtConfig, secretkey),JwtUnameAndPassAuthFilter.class)
		.authorizeRequests()
		.antMatchers("/","/login","index","/css/*","/js/*").permitAll()
		.antMatchers("/api/**").hasRole(AppUserRole.STUDENT.name())
//		.antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(AppUserPermission.COURSE_WRITE.getPermission())
//		.antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(AppUserPermission.COURSE_WRITE.getPermission())
//		.antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(AppUserPermission.COURSE_WRITE.getPermission())
//		.antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(AppUserRole.ADMIN.name(),AppUserRole.ADMINTRAINEE.name())
		.anyRequest()
		.authenticated();


//		because of JWT
//		.and()
//		.formLogin()
//		.loginPage("/login").permitAll()
//		.defaultSuccessUrl("/courses",true)
//		.and()
//		.rememberMe()
//			.tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))
//			.key("SomethingSecure")
//		.and()
//		.logout()
//			.logoutUrl("/logout")
//			.logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET")) //delete when csrf enabled
//			.clearAuthentication(true)
//			.invalidateHttpSession(true)
//			.deleteCookies("JSESSIONID","remember-me")
//			.logoutSuccessUrl("/login");
	}

//	@Override
//	@Bean
//	protected UserDetailsService userDetailsService() {
//		UserDetails Jackuser = User.builder()
//				.username("Jack")
//				.password(passwordEncoder.encode("passwordJack"))
////				.roles("ADMIN")	//Role_Student
////				.roles(AppUserRole.ADMIN.name())	//Role_Admin
//				.authorities(AppUserRole.ADMIN.getGrantedAuthorities())
//				.build();
//
//		UserDetails Abiuser = User.builder()
//				.username("Abi")
//				.password(passwordEncoder.encode("passwordAbi"))
////				.roles(AppUserRole.STUDENT.name())	//Role_Student
//				.authorities(AppUserRole.STUDENT.getGrantedAuthorities())
//				.build();
//
//		UserDetails Tomuser = User.builder()
//				.username("Tom")
//				.password(passwordEncoder.encode("passwordTom"))
////				.roles(AppUserRole.ADMINTRAINEE.name())	//Role_Student
//				.authorities(ADMINTRAINEE.getGrantedAuthorities())
//				.build();
//
//		return new InMemoryUserDetailsManager(
//				Jackuser,
//				Abiuser,
//				Tomuser
//				);
//	}

	@Bean
	public DaoAuthenticationProvider daoAuthProvider()
	{
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(appUserService);
		return provider;
	}
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthProvider());
	}
}
