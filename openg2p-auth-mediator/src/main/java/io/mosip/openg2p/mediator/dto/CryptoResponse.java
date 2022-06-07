package io.mosip.openg2p.mediator.dto;

import lombok.Data;

@Data
public class CryptoResponse {
    private String encryptedKey;
    private String encryptedBody;
    private String hmacDigest;
    private String thumbprint;
}
