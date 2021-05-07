package de.samurus.discbot.backend;


import java.util.Objects;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequestEntityConverter;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private static final String SAMURUS_BOT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:33.0) Gecko/20100101 Firefox/33.0";

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.oauth2Login()
        .tokenEndpoint().accessTokenResponseClient(accessTokenResponseClient())
        .and()
        .userInfoEndpoint().userService(userService());
  }

  @Bean
  public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
    DefaultAuthorizationCodeTokenResponseClient client = new DefaultAuthorizationCodeTokenResponseClient();

    client.setRequestEntityConverter(new OAuth2AuthorizationCodeGrantRequestEntityConverter() {
      @Override
      public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest oauth2Request) {
        return addUserAgentHeader(Objects.requireNonNull(super.convert(oauth2Request)));
      }
    });

    return client;
  }

  @Bean
  public OAuth2UserService<OAuth2UserRequest, OAuth2User> userService() {
    DefaultOAuth2UserService service = new DefaultOAuth2UserService();

    service.setRequestEntityConverter(new OAuth2UserRequestEntityConverter() {
      @Override
      public RequestEntity<?> convert(OAuth2UserRequest userRequest) {
        return addUserAgentHeader(
            Objects.requireNonNull(super.convert(userRequest)));
      }
    });

    return service;
  }

  private RequestEntity<?> addUserAgentHeader(RequestEntity<?> request) {
    HttpHeaders headers = new HttpHeaders();
    headers.putAll(request.getHeaders());
    headers.add(HttpHeaders.USER_AGENT, SAMURUS_BOT_USER_AGENT);

    return new RequestEntity<>(request.getBody(), headers, request.getMethod(), request.getUrl());
  }

}



