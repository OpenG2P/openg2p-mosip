package io.mosip.openg2p.mediator.service;

import io.mosip.openg2p.mediator.dto.CryptoResponse;
import io.mosip.openg2p.mediator.exception.BaseCheckedException;
import io.mosip.openg2p.mediator.util.CryptoUtil;
import io.mosip.openg2p.mediator.util.TokenUtil;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.Period;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

@Service
public class DemoAuthService {

    private final Logger LOGGER = LoggerFactory.getLogger(DemoAuthService.class);

    @Autowired
    private TokenUtil tokenUtil;

    @Autowired
    private CryptoUtil cryptoUtil;

    @Value("${mosip.ida.auth.url}")
    private String idaAuthUrl;
    @Value("${mosip.ida.auth.domain.uri}")
    private String idaAuthDomainUri;
    @Value("${mosip.ida.auth.version}")
    private String idaAuthVersion;
    @Value("${mosip.ida.auth.env}")
    private String idaAuthEnv;
    @Value("${mosip.ida.auth.request.id}")
    private String idaAuthReqId;
    @Value("${mosip.openg2p.partner.username}")
    private String partnerUsername;
    @Value("${mosip.openg2p.partner.apikey}")
    private String partnerApikey;
    @Value("${mosip.openg2p.partner.misp.lk}")
    private String partnerMispLK;
    @Value("${mosip.openg2p.demoAuth.full.address.order}")
    private String fullAddressOrder;
    @Value("${mosip.openg2p.demoAuth.full.address.separator}")
    private String fullAddressSeparator;
    @Value("${mosip.openg2p.demoAuth.dob.pattern}")
    private String mosipDobPattern;
    @Value("${openg2p.dob.pattern}")
    private String openg2pDobPattern;

    private SecureRandom secureRandom = null;

    public String authenticate(String upstreamRequest) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        JSONObject upstreamJson;
        String vid,language,dob,fullName,phone,email,gender,fullAddress;
        try{
            upstreamJson = new JSONObject(upstreamRequest);
            language = convertLangCode(upstreamJson.getString("lang"));
            dob = convertDOB(upstreamJson.getString("dateOfBirth"), openg2pDobPattern, mosipDobPattern);
            fullName = upstreamJson.getString("fullname");
            phone = upstreamJson.getString("phone");
            email = upstreamJson.getString("email");
            gender = upstreamJson.getString("gender");
            fullAddress = getFullAddressFromJson(upstreamJson, fullAddressOrder, fullAddressSeparator);
            vid = upstreamJson.getString("id");
        } catch (JSONException je) {
            String error = "Unable to parse request JSON";
            LOGGER.error(error, je);
            return returnErrorResponse(sdf.format(new Date()),error);
        } catch (BaseCheckedException e) {
            LOGGER.error(e.getMessage(), e);
            return returnErrorResponse(sdf.format(new Date()),e.getMessage());
        }

        CryptoResponse encryptedRequest;
        String request = "{" +
            "\"timestamp\": \"" + sdf.format(new Date()) + "\"" + "," +
            "\"demographics\": {" +
                //"\"age\": \"" + Period.between(LocalDate.parse(dob, DateTimeFormatter.ofPattern(mosipDobPattern)), LocalDate.now()).getYears() + "\"" + "," +
                //"\"dob\": \"" + dob + "\"" + "," +
                "\"phoneNumber\": \"" + phone + "\"" + "," +
                "\"emailId\": \"" + email + "\"" + "," +
                "\"name\": [" +
                    "{" +
                        "\"language\": \"" + language + "\"" + "," +
                        "\"value\": \"" + fullName + "\"" +
                    "}" +
                "]" + "," +
                "\"gender\": [" +
                    "{" +
                        "\"language\": \"" + language + "\"" + "," +
                        "\"value\": \"" + gender + "\"" +
                    "}" +
                "]" + "," +
                "\"fullAddress\": [" +
                    "{" +
                        "\"language\": \"" + language + "\"" + "," +
                        "\"value\": \"" + fullAddress + "\"" +
                    "}" +
                "]" + "," +
                "\"metadata\": {}" +
            "}" + "," +
            "\"biometrics\": []" +
        "}";
        try{
            encryptedRequest = cryptoUtil.encryptSign(request);
        } catch(BaseCheckedException e) {
            String error = "Demo Auth Crypto - Error while Encrypting / Signing Request";
            LOGGER.error(error, e);
            return returnErrorResponse(sdf.format(new Date()),error);
        }
        LOGGER.info("Demo Auth Request - Successfully Encrypted Request");

        String downStreamRequest = "{" +
            "\"id\": \"" + idaAuthReqId + "\"" + "," +
            "\"version\": \"" + idaAuthVersion + "\"" + "," +
            "\"individualId\": \"" + vid + "\"" + "," +
            //"\"individualIdType\": \"VID\"" + "," +
            "\"transactionID\": \"" + randomAlphaNumericString(10) + "\"" + "," +
            "\"requestTime\": \"" + sdf.format(new Date()) + "\"" + "," +
            "\"specVersion\": \"" + idaAuthVersion + "\"" + "," +
            "\"thumbprint\": \"" + encryptedRequest.getThumbprint() + "\"" + "," +
            "\"domainUri\": \"" + idaAuthDomainUri + "\"" + "," +
            "\"env\": \"" + idaAuthEnv + "\"" + "," +
            "\"requestedAuth\": {" +
                "\"demo\": true" + "," +
                "\"pin\": false" + "," +
                "\"otp\": false" + "," +
                "\"bio\": false" +
            "}" + "," +
            "\"consentObtained\": true" + "," +
            "\"requestHMAC\": \"" + encryptedRequest.getHmacDigest() + "\"" + "," +
            "\"requestSessionKey\": \"" + encryptedRequest.getEncryptedKey() + "\"" + "," +
            "\"request\": \"" + encryptedRequest.getEncryptedBody() + "\"" + "," +
            "\"metadata\": {}" +
        "}";

        String jwtSign;
        try{
            jwtSign = cryptoUtil.jwtSign(downStreamRequest);
        } catch (BaseCheckedException e) {
            String error = "Demo Authentication JwtSign - Error getting signature";
            LOGGER.error(error,e);
            return returnErrorResponse(sdf.format(new Date()),error);
        }

        String token;
        try {
            token = tokenUtil.getPartnerAuthToken();
        } catch (BaseCheckedException e) {
            String error = "Demo Authentication Token - Error getting partner auth token";
            LOGGER.error(error,e);
            return returnErrorResponse(sdf.format(new Date()),error);
        }

        String response;
        try{
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.add("Authorization","Authorization=" + token);
            headers.add("Signature",jwtSign);
            HttpEntity<String> reqEnt = new HttpEntity<>(downStreamRequest,headers);
            RestTemplate restTemplate = new RestTemplate();
            response = restTemplate.postForObject(idaAuthUrl+"/"+partnerMispLK+"/"+partnerUsername+"/"+partnerApikey,reqEnt,String.class);
        } catch (Exception e) {
            String error = "Demo Authentication - Error while Authentication";
            LOGGER.error(error, e);
            return returnErrorResponse(sdf.format(new Date()),error + ": " + getStackTrace(e));
        }
        return response;
    }

    public static String getStackTrace(Throwable e){
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        return sw.toString();
    }

    public String randomAlphaNumericString(int size){
        if(secureRandom == null)
            secureRandom = new SecureRandom();
        return secureRandom.ints(48, 123)
            .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
            .limit(size)
            .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
            .toString();
    }

    private String returnErrorResponse(String timestamp, String error){
        return "{" +
            "\"responseTime\": \"" + timestamp + "\"" + "," +
            "\"response\": null" + "," +
            "\"errors\":[" +
                "{" +
                    "\"errorMessage\": \"" + error + "\"" + "," +
                    "\"actionMessage\": \"\"" + "," +
                    "\"errorCode\": \"\"" + "," +
                "}" +
            "]" +
        "}";
    }

    private String getFullAddressFromJson(JSONObject json, String order, String separator) throws JSONException{
        String fAddress = "";
        String[] orderArr = order.replaceAll("\\s","").split(",");
        for(int i=0; i<orderArr.length; i++){
            if(i>0)fAddress+=separator.replaceAll("'","");
            fAddress+=json.getString(orderArr[i]);
        }
        return fAddress;
    }

    private String convertLangCode(String langCode){
        String[] localeArray = langCode.split("-");
        try {
            if (localeArray.length > 1) {
                return new Locale(localeArray[0], localeArray[1]).getISO3Language();
            } else {
                localeArray = langCode.split("_");
                if (localeArray.length > 1) {
                    return new Locale(localeArray[0], localeArray[1]).getISO3Language();
                } else {
                    return new Locale(langCode).getISO3Language();
                }
            }
        } catch (Exception e) {
            LOGGER.error("Unable to convert language code.", e);
            return langCode;
        }
    }

    private String convertDOB(String dob, String originalPattern, String targetPattern) throws BaseCheckedException{
        SimpleDateFormat originalFormat = new SimpleDateFormat(originalPattern);
        SimpleDateFormat targetFormat = new SimpleDateFormat(targetPattern);
        try{
            Date date = originalFormat.parse(dob);
            return targetFormat.format(date);
        } catch (Exception e) {
            throw new BaseCheckedException("","Unable to convert DOB",e);
        }
    }
}
