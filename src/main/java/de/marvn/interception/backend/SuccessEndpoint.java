package de.marvn.interception.backend;

import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.ResponseEntity.HeadersBuilder;
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
public class SuccessEndpoint {

  @Value("${spring.security.oauth2.client.registration.discord.client-id:default-client-id}")
  private String clientId;
  @Value("${spring.security.oauth2.client.registration.discord.client-secret:default-client-secret}")
  private String clientSecret;
  @Value("${server.heroku.url:http://www.dummy.de/}")
  private String hostUrl;


  @GetMapping("/oauth2/code/discord")
  public ResponseEntity<String> getCustomers(@RequestParam String code, @RequestParam String state, @RequestHeader Map<String, String> headers) {

    RestTemplate restTemplate = new RestTemplate();
    HttpHeaders requestHeader = new HttpHeaders();
    requestHeader.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

    MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
    map.add("client-id",clientId);
    map.add("client_secret",clientSecret);
    map.add("grant_type", "authorization_code");
    map.add("redirect_uri", hostUrl+"/login2/oauth2/code/discord");
    map.add("code", code);

    HttpEntity<MultiValueMap<String, String>> requestBody = new HttpEntity<>(map, requestHeader);

    ResponseEntity<String> response =
        restTemplate.exchange("https://foo/api/v3/projects/1/labels",
            HttpMethod.POST,
            requestBody,
            String.class);

    return new ResponseEntity<String>(String.valueOf(requestBody), HttpStatus.OK);
  }


}
