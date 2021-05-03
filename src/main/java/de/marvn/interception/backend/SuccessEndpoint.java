package de.marvn.interception.backend;

import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/login2")
public class SuccessEndpoint {

  @GetMapping("/oauth2/code/discord")
  public ResponseEntity<String> getCustomers(@RequestParam String code, @RequestParam String id, @RequestHeader Map<String, String> headers) {

    return new ResponseEntity<String>(
        String.format("code = "+code+"id= "+ id + "Listed %d headers=", headers.size()), HttpStatus.OK);
  }


}
