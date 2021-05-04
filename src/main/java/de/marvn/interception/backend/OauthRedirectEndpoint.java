package de.marvn.interception.backend;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.ResponseEntity.HeadersBuilder;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/login2")
public class OauthRedirectEndpoint <B extends HttpSecurityBuilder<B>>
		extends AbstractAuthenticationFilterConfigurer<B, OAuth2LoginConfigurer<B>, OAuth2LoginAuthenticationFilter> {

  @Value("${spring.security.oauth2.client.registration.discord.client-id:default-client-id}")
  private String clientId;
  @Value("${spring.security.oauth2.client.registration.discord.client-secret:default-client-secret}")
  private String clientSecret;
  @Value("${server.heroku.url:http://www.dummy.de/}")
  private String hostUrl;

  private final Logger log = LoggerFactory.getLogger(getClass());


  @GetMapping("/oauth2/code/discord")
  public ResponseEntity<String> getCustomers2(@RequestParam String code, @RequestParam String state, @RequestHeader Map<String, String> headers) {

    log.info("code =" + code);
    RestTemplate restTemplate = new RestTemplate();
    HttpHeaders requestHeader = new HttpHeaders();
    requestHeader.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    requestHeader.add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:33.0) Gecko/20100101 Firefox/33.0");
    requestHeader.add("Connection", "keep-alive");

    MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
    map.add("client_id",clientId);
    map.add("client_secret",clientSecret);
    map.add("grant_type", "authorization_code");
    map.add("redirect_uri", hostUrl+"/login2/oauth2/code/discord");
    map.add("code", code);

    HttpEntity<MultiValueMap<String, String>> stringHttpEntity = new HttpEntity<>(map,
        requestHeader);

    String response =
        restTemplate.postForObject("https://discord.com/api/oauth2/token",
            stringHttpEntity, String.class);
//    OAuth2AccessTokenResponse oAuth2AccessTokenResponse = OAuth2AccessTokenResponse.withToken().build()

    return new ResponseEntity<String>(String.valueOf(response), HttpStatus.OK);
  }


  @Override
  protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
    return new AntPathRequestMatcher(loginProcessingUrl);
  }
}
