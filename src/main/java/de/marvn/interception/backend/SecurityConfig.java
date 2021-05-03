package de.marvn.interception.backend;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

@Configuration
public class SecurityConfig {

  @Value("${spring.security.oauth2.client.registration.discord.client-id:default-client-id}")
  private String clientId;
  @Value("${spring.security.oauth2.client.registration.discord.client-secret:default-client-secret}")
  private String clientSecret;

  @Value("${server.heroku.url:http://www.dummy.de/}")
  private String hostUrl;

  @EnableWebSecurity
  public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      http
          .authorizeRequests(authorizeRequests ->
              authorizeRequests
                  .anyRequest().authenticated()
          )
          .oauth2Login(withDefaults());
    }
  }

  @Bean
  public ClientRegistrationRepository clientRegistrationRepository() {
    return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
  }

  private ClientRegistration googleClientRegistration() {
    clientId = "838676421177507880";
    clientSecret = "73BYE4KcrBmvzvWsQZdxgncDJYV8-Hk_";
    return ClientRegistration.withRegistrationId("discord")
        .clientId(clientId)
        .clientSecret(clientSecret)
        .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri(hostUrl+"/login/oauth2/code/discord")
        .scope("email", "connections")
        .authorizationUri("https://discord.com/api/oauth2/authorize")
        .tokenUri("https://discord.com/api/oauth2/token")
        .userInfoUri("https://www.discord.com/users/@me")
        .userNameAttributeName(IdTokenClaimNames.SUB)
//        .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
        .clientName("Discord")
        .build();
    //https://discord.com/api/oauth2/authorize?client_id=838676421177507880&permissions=0&redirect_uri=https%3A%2F%2Fwww.google.com%2Fsearch%3Fq%3Dteswt&response_type=code&scope=email%20connections%20bot
  }
}
