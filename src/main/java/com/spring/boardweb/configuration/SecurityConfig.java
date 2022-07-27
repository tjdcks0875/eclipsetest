package com.spring.boardweb.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
//security의 filterchain을 구현하기 위해 선언
@EnableWebSecurity
public class SecurityConfig {
	 //비밀번호 암호화 인코더 추가
	 @Bean
	 PasswordEncoder passwordEncoder() {
		 return new BCryptPasswordEncoder();
	 }
	   
	 
     @Bean
     public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
    	 //authorizeHttpRequests로 요청에 대한 권한을 설정할 수 있다.
    	 http.authorizeRequests().antMatchers("/").permitAll()
    	                             .antMatchers("/user/**").permitAll()
    	                             .antMatchers("/board/**").access("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    	                             .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
    	                             .antMatchers("/css/**").permitAll()
    	                             .antMatchers("/js/**").permitAll()
    	                             .antMatchers("/upload/**").permitAll()
    	                             .antMatchers("/images/**").permitAll()    	                             
    	                             .anyRequest().authenticated();
    	 
    	 //로그인 로그아웃 처리
    	 http.formLogin()
    	     .loginPage("/user/login")
    	     //시큐리티에서는 id를 username
    	     //          pw는 password로 사용하기 때문에
    	     //          게시판에서 사용하는 키 값으로 지정해줌
    	     .usernameParameter("userId")
    	     .passwordParameter("userPw")
    	     //다음 요청이 들어오면 시큐리티가 낚아채서 로그인처리함
    	     .loginProcessingUrl("/user/loginProc")
    	     //로그인 성공 시 이동할 페이지 지정
    	     .defaultSuccessUrl("/");
    	 http.logout()
    	     .invalidateHttpSession(true)
    	     .logoutSuccessUrl("/user/login");
    	 
    	 //크로스 도메인 공격 방지 설정
    	 http.csrf().disable();
    	 
    	 return http.build();
     }
}
