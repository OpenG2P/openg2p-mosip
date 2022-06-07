package io.mosip.openg2p.mediator.util;

import io.mosip.openg2p.mediator.exception.BaseCheckedException;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.io.PrintWriter;
import java.io.StringWriter;

@Component
public class TokenUtil {
    private final Logger LOGGER = LoggerFactory.getLogger(TokenUtil.class);

    public static String TOKEN_GENERATION_FAILED_MESSAGE = "Failed to Generate token.";
    public static String TOKEN_GENERATION_FAILED_CODE = "OPG-TKN-01";

    @Value("${mosip.openg2p.partner.client.id}")
    private String partnerClientId;
    @Value("${mosip.openg2p.partner.client.secret}")
    private String partnerClientSecret;
    @Value("${mosip.openg2p.partner.username}")
    private String partnerUsername;
    @Value("${mosip.openg2p.partner.password}")
    private String partnerPassword;
    @Value("${mosip.iam.token_endpoint}")
    private String iamTokenEndpoint;

    private String getOIDCToken(String tokenEndpoint, String clientId, String clientSecret, String username, String password, String grantType) throws BaseCheckedException {
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.set("grant_type", grantType);
        formData.set("client_id", clientId);
        if(clientSecret!=null)formData.set("client_secret", clientSecret);
        if(username!=null)formData.set("username", username);
        if(password!=null)formData.set("password", password);

        try {
            String responseJson = new RestTemplate().postForObject(tokenEndpoint, formData, String.class);
            if (responseJson == null || responseJson.isEmpty()) {
                throw new BaseCheckedException(TOKEN_GENERATION_FAILED_CODE,TOKEN_GENERATION_FAILED_MESSAGE);
            }
            return new JSONObject(responseJson).getString("access_token");
        } catch (JSONException | RestClientException e) {
            throw new BaseCheckedException(TOKEN_GENERATION_FAILED_CODE,TOKEN_GENERATION_FAILED_MESSAGE,e);
        }
    }

    private String getOIDCToken(String tokenEndpoint, String clientId, String clientSecret, String username, String password) throws BaseCheckedException{
        return getOIDCToken(tokenEndpoint,clientId,clientSecret,username,password,"password");
    }

    private String getOIDCToken(String tokenEndpoint, String clientId, String username, String password) throws BaseCheckedException{
        return getOIDCToken(tokenEndpoint,clientId,null,username,password);
    }

    private String getOIDCToken(String tokenEndpoint, String clientId, String clientSecret) throws BaseCheckedException{
        return getOIDCToken(tokenEndpoint,clientId,clientSecret,null,null,"client_credentials");
    }

    public String getPartnerAuthToken() throws BaseCheckedException{
        return getOIDCToken(iamTokenEndpoint, partnerClientId, partnerClientSecret, partnerUsername, partnerPassword);
    }
}
