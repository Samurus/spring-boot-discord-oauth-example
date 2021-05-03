package de.marvn.interception.backend;

import java.util.Arrays;
import java.util.Collections;
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
    System.out.println("code =" + code);
    RestTemplate restTemplate = new RestTemplate();
    HttpHeaders requestHeader = new HttpHeaders();
    requestHeader.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    requestHeader.setAccept(Collections.singletonList(MediaType.ALL));

//    MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
//    map.add("client_id",clientId);
//    map.add("client_secret",clientSecret);
//    map.add("grant_type", "authorization_code");
//    map.add("redirect_uri", hostUrl+"/login2/oauth2/code/discord");
//    map.add("code", code);

    String body = "client_id="+clientId+"&"+
    "client_secret="+clientSecret+"&"+
    "grant_type="+"authorization_code"+"&"+
    "redirect_uri="+hostUrl+"/login2/oauth2/code/discord"+"&"+
    "code="+code;

    HttpEntity<String> stringHttpEntity = new HttpEntity<>(body, requestHeader);

    System.out.println(stringHttpEntity);

    ResponseEntity<String> response =
        restTemplate.exchange("https://discord.com/api/oauth2/token",
            HttpMethod.POST,
            stringHttpEntity,
            String.class);

    System.out.println(response);

    return new ResponseEntity<String>(String.valueOf(response), HttpStatus.OK);
  }


}
