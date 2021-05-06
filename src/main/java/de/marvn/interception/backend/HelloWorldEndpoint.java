package de.marvn.interception.backend;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class HelloWorldEndpoint {

  @Autowired
  private OAuth2AuthorizedClientService authorizedClientService;

  @GetMapping()
  public String getLoginInfo(Model model, OAuth2AuthenticationToken authentication) {
    OAuth2AuthorizedClient client = authorizedClientService
        .loadAuthorizedClient(
            authentication.getAuthorizedClientRegistrationId(),
            authentication.getName());

    return "Login accomplished. Hello " + authentication.getPrincipal().getAttributes().get("username");
  }

  @GetMapping("/test")
  public String getTest(Model model, OAuth2AuthenticationToken authentication) {
    return "Testseite. Hello " + authentication.getPrincipal().getAttributes().get("username");
  }

}
