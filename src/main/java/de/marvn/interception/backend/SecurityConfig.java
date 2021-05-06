package de.marvn.interception.backend;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequestEntityConverter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.MapOAuth2AccessTokenResponseConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

@Configuration
public class SecurityConfig {

  @Value("${spring.security.oauth2.client.registration.discord.client-id:default-client-id}")
  private String clientId;
  @Value("${spring.security.oauth2.client.registration.discord.client-secret:default-client-secret}")
  private String clientSecret;

  @Value("${server.heroku.url:http://www.dummy.de/}")
  private String hostUrl;

  @EnableWebSecurity
  public class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      http
          .authorizeRequests(authorizeRequests ->
              authorizeRequests

                  .anyRequest().authenticated()
          )
          .oauth2Login()
          .userInfoEndpoint()
          .userService(customDefaultOAuth2UserService())
          .and()
          .tokenEndpoint()
          .accessTokenResponseClient(accessTokenResponseClient());
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
        .redirectUri(hostUrl + "/login/oauth2/code/discord")
        .scope("email", "identify", "guilds", "messages.read", "connections")
        .authorizationUri("https://discord.com/api/oauth2/authorize")
        .tokenUri("https://discord.com/api/oauth2/token")
        .userInfoUri("https://www.discord.com/users/@me")
        .userNameAttributeName("id")
        .clientName("Discord")
        .build();
  }


  @Bean
  public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
    DefaultAuthorizationCodeTokenResponseClient accessTokenResponseClient = new DefaultAuthorizationCodeTokenResponseClient();
    accessTokenResponseClient.setRequestEntityConverter(new CustomRequestEntityConverter());

    OAuth2AccessTokenResponseHttpMessageConverter tokenResponseHttpMessageConverter = new OAuth2AccessTokenResponseHttpMessageConverter();
    tokenResponseHttpMessageConverter
        .setTokenResponseConverter(new MapOAuth2AccessTokenResponseConverter());
    RestTemplate restTemplate = new RestTemplate(
        Arrays.asList(new FormHttpMessageConverter(), tokenResponseHttpMessageConverter));
    restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
    accessTokenResponseClient.setRestOperations(restTemplate);
    return accessTokenResponseClient;
  }

  @Bean
  public DiscordOAuth2UserService customDefaultOAuth2UserService() {
    return new DiscordOAuth2UserService();
  }

  private class CustomRequestEntityConverter implements
      Converter<OAuth2AuthorizationCodeGrantRequest, RequestEntity<?>> {

    private OAuth2AuthorizationCodeGrantRequestEntityConverter defaultConverter;

    public CustomRequestEntityConverter() {
      defaultConverter = new OAuth2AuthorizationCodeGrantRequestEntityConverter();
    }

    @Override
    public RequestEntity<?> convert(OAuth2AuthorizationCodeGrantRequest req) {
      RequestEntity<?> entity = defaultConverter.convert(req);
      MultiValueMap<String, String> body = (MultiValueMap<String, String>) entity.getBody();
      body.set("client_id", clientId);
      body.set("client_secret", clientSecret);

      HttpHeaders headers = new HttpHeaders();
      headers.add("User-Agent",
          "Mozilla/5.0 (X11; Linux x86_64; rv:33.0) Gecko/20100101 Firefox/33.0");
      headers.add("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8");

      return new RequestEntity<>(body, headers, entity.getMethod(), entity.getUrl());
    }

  }

  public static class DiscordOAuth2UserService extends DefaultOAuth2UserService {

    private static final String MISSING_USER_INFO_URI_ERROR_CODE = "missing_user_info_uri";

    private static final String MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE = "missing_user_name_attribute";

    private static final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";


    private Converter<OAuth2UserRequest, RequestEntity<?>> requestEntityConverter = new OAuth2UserRequestEntityConverter();

    private static final ParameterizedTypeReference<Map<String, Object>> PARAMETERIZED_RESPONSE_TYPE = new ParameterizedTypeReference<Map<String, Object>>() {
    };


    private RestOperations restOperations;

    public DiscordOAuth2UserService() {
      RestTemplate restTemplate = new RestTemplate();
      restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
      this.restOperations = restTemplate;
    }

    @SneakyThrows
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
      Assert.notNull(userRequest, "userRequest cannot be null");
      if (!StringUtils
          .hasText(userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint()
              .getUri())) {
        OAuth2Error oauth2Error = new OAuth2Error(MISSING_USER_INFO_URI_ERROR_CODE,
            "Missing required UserInfo Uri in UserInfoEndpoint for Client Registration: "
                + userRequest.getClientRegistration().getRegistrationId(),
            null);
        throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
      }
      String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
          .getUserInfoEndpoint()
          .getUserNameAttributeName();
      if (!StringUtils.hasText(userNameAttributeName)) {
        OAuth2Error oauth2Error = new OAuth2Error(MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE,
            "Missing required \"user name\" attribute name in UserInfoEndpoint for Client Registration: "
                + userRequest.getClientRegistration().getRegistrationId(),
            null);
        throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
      }

      //https://discord.com/developers/docs/resources/user
      //{"id": "168406870564798464", "username": "Samurus", "avatar": "57e5aec8320d9b7cb231593f505c08ef", "discriminator": "8617", "public_flags": 0, "flags": 0, "locale": "en-US", "mfa_enabled": false, "premium_type": 1, "email": "conann233@web.de", "verified": true}
      HttpHeaders headers = new HttpHeaders();
      headers.add("User-Agent",
          "Mozilla/5.0 (X11; Linux x86_64; rv:33.0) Gecko/20100101 Firefox/33.0");
      headers.add("Authorization", "Bearer " + userRequest.getAccessToken().getTokenValue());
      ResponseEntity<String> response = new RestTemplate()
          .exchange("https://discord.com/api/users/@me", HttpMethod.GET, new HttpEntity<>(headers),
              String.class, "");
      Map<String, Object> userAttributes = new ObjectMapper()
          .readValue(response.getBody(), HashMap.class);

      Set<GrantedAuthority> authorities = new LinkedHashSet<>();
      authorities.add(new OAuth2UserAuthority(userAttributes));
      OAuth2AccessToken token = userRequest.getAccessToken();
      for (String authority : token.getScopes()) {
        authorities.add(new SimpleGrantedAuthority("SCOPE_" + authority));
      }
      return new DefaultOAuth2User(authorities, userAttributes, userNameAttributeName);
    }


  }
}

