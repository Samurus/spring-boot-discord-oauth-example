package de.marvn.interception.backend;

@RestController
@RequestMapping("/login")
public class SuccessEndpoint {

  @GetMapping("/oauth2/code/discord")
  public String getCustomers(@RequestHeader Map<String, String> headers) {
    return new ResponseEntity<String>(
        String.format("Listed %d headers", headers.size()), HttpStatus.OK);
  }


}
