package de.marvn.interception.backend;

import static org.springframework.security.config.Customizer.withDefaults;

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
    return ClientRegistration.withRegistrationId("discord")
        .clientId("discord-client-id")
        .clientSecret("discord-client-secret")
        .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}")
        .scope("openid", "profile", "email", "address", "phone")
        .authorizationUri("https://discord.com/api/oauth2/authorize")
        .tokenUri("https://discord.com/api/oauth2/token")
        .userInfoUri("https://www.discord.com/users/@me")
        .userNameAttributeName(IdTokenClaimNames.SUB)
//        .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
        .clientName("Discord")
        .build();
  }
}
