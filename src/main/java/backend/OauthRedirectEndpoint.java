package backend;

import backend.gson.TokenQuery;
import com.google.gson.Gson;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api")
public class OauthRedirectEndpoint <B extends HttpSecurityBuilder<B>>
		extends AbstractAuthenticationFilterConfigurer<B, OAuth2LoginConfigurer<B>, OAuth2LoginAuthenticationFilter> {

  @Value("${spring.security.oauth2.client.registration.discord.client-id:default-client-id}")
  private String clientId;
  @Value("${spring.security.oauth2.client.registration.discord.client-secret:default-client-secret}")
  private String clientSecret;
  @Value("${server.heroku.url}")
  private String hostUrl;

  private final Logger log = LoggerFactory.getLogger(getClass());


  @GetMapping("/discord-callback")
  public ResponseEntity<String> getCustomers2(@RequestParam String code, @RequestParam String state) {

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
    map.add("redirect_uri", hostUrl+"/api/discord-callback");
    map.add("code", code);

    HttpEntity<MultiValueMap<String, String>> stringHttpEntity = new HttpEntity<>(map,
        requestHeader);

    String response =
        restTemplate.postForObject("https://discord.com/api/oauth2/token",
            stringHttpEntity, String.class);

    TokenQuery r = new Gson().fromJson(response, TokenQuery.class);

    return new ResponseEntity<String>("AccessToken = " +r.getAccessToken() + " Successfull!", HttpStatus.OK);
  }


  @Override
  protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
    return new AntPathRequestMatcher(loginProcessingUrl);
  }
}
