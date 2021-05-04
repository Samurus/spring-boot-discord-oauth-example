package backend.gson;

public class TokenQuery {

    String access_token;
    String token_type;
    String expires_in;
    String refresh_token;
    String scope;

    public String getAccessToken(){
        return this.access_token;
    }

    public String getTokenType(){
        return this.token_type;
    }

    public String getExpiresIn(){
        return this.expires_in;
    }

    public String getRefreshToken(){
        return this.refresh_token;
    }

    public String getScope(){
        return this.scope;
    }

}
