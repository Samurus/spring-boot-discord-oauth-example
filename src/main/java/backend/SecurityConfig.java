package backend;

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

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class SecurityConfig {

  @Value("${spring.security.oauth2.client.registration.discord.client-id:default-client-id}")
  private String clientId;
  @Value("${spring.security.oauth2.client.registration.discord.client-secret:default-client-secret}")
  private String clientSecret;

  @Value("${server.heroku.url}")
  private String hostUrl;

  @EnableWebSecurity
  public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      http.authorizeRequests().antMatchers("/api/**").permitAll();
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
    return new InMemoryClientRegistrationRepository(this.discordClientRegistration());
  }

  private ClientRegistration discordClientRegistration() {
    return ClientRegistration.withRegistrationId("discord")
        .clientId(clientId)
        .clientSecret(clientSecret)
        .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri(hostUrl+"/api/discord-callback")
        .scope("email","identify","guilds")
        .authorizationUri("https://discord.com/api/oauth2/authorize")
        .tokenUri("https://discord.com/api/oauth2/token")
        .userInfoUri("https://www.discord.com/users/@me")
        .userNameAttributeName(IdTokenClaimNames.SUB)
        .clientName("Discord")
        .build();
  }
}
