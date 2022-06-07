package io.mosip.openg2p.mediator.util;

import io.mosip.openg2p.mediator.dto.CryptoResponse;
import io.mosip.openg2p.mediator.exception.BaseCheckedException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.FileReader;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;


@Component
public class CryptoUtil {

    private final Logger LOGGER = LoggerFactory.getLogger(CryptoUtil.class);

    private final static String SIGNATURE_FAILURE_CODE="OPG-SIG-01";
    private final static String SIGNATURE_FAILURE_MESSAGE="Failed to generate signature";
    private final static String SYMMETRIC_ENCRYPT_FAILURE_CODE="OPG-ENC-01";
    private final static String SYMMETRIC_ENCRYPT_FAILURE_MESSAGE="Failed to symmetric encrypt";
    private final static String ASYMMETRIC_ENCRYPT_FAILURE_CODE="OPG-ENC-11";
    private final static String ASYMMETRIC_ENCRYPT_FAILURE_MESSAGE="Failed to asymmetric encrypt";
    private final static String DIGEST_ENCRYPT_FAILURE_CODE="OPG-ENC-21";
    private final static String DIGEST_ENCRYPT_FAILURE_MESSAGE="Failed to message digest";

    @Value("${mosip.ida.crypto.symmetric-algorithm-name}")
    private String symmetricAlgoName;
    @Value("${mosip.ida.crypto.symmetric-key-length}")
    private String symmetricKeyLength;
    @Value("${mosip.ida.crypto.symmetric.gcm-tag-length}")
    private String symmetricGcmTagLength;

    @Value("${mosip.ida.crypto.asymmetric-algorithm-name}")
    private String asymmetricAlgoName;
    @Value("${mosip.ida.crypto.asymmetric-key.cert.path}")
    private String encryptCertPath;
    private String encryptCertThumbprint;

    @Value("${mosip.ida.crypto.sign-algorithm-name}")
    private String signAlgoName;
    @Value("${mosip.ida.crypto.sign.privkey.path}")
    private String signPrivKeyPath;
    private PrivateKey signPrivKey;
    @Value("${mosip.ida.crypto.sign.cert.path}")
    private String signCertPath;
    private X509Certificate signCert;

    private Cipher asymmetricEncryptCipher;
    private KeyGenerator symmetrickeyGen;
    private SecureRandom secureRandom;

    @PostConstruct
    public void init(){
        secureRandom = new SecureRandom();
        symmetricInit();
        asymmetricInit();
        signInit();
    }

    private void symmetricInit() {
        try {
            symmetrickeyGen = KeyGenerator.getInstance(symmetricAlgoName.split("/")[0]);
            symmetrickeyGen.init(Integer.parseInt(symmetricKeyLength));
        } catch (Exception e) {
            throw new RuntimeException("Unable to init keygenerator.", e);
        }
    }

    private void asymmetricInit() {
        X509Certificate encryptCert;
        try {
            PEMParser parser = new PEMParser(new FileReader(encryptCertPath));
            encryptCert = new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) parser.readObject());
        } catch (Exception e) {
            throw new RuntimeException("Unable to Read Encryption Public Key from given path: " + encryptCertPath, e);
        }

        try {
            asymmetricEncryptCipher = Cipher.getInstance(asymmetricAlgoName);
            OAEPParameterSpec oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            asymmetricEncryptCipher.init(Cipher.ENCRYPT_MODE, encryptCert.getPublicKey(), oaepParams);
        } catch (Exception e) {
            throw new RuntimeException("Unable to create asymmetric cipher.", e);
        }

        try{
            encryptCertThumbprint = Base64.encodeBase64String(MessageDigest.getInstance("SHA-256").digest(encryptCert.getEncoded()));
        } catch(Exception e) {
            throw new RuntimeException("Unable to generate thumbprint.", e);
        }
    }

    private void signInit() {
        try {
            PEMParser parser = new PEMParser(new FileReader(signPrivKeyPath));
            signPrivKey = new JcaPEMKeyConverter().getPrivateKey(((PEMKeyPair) parser.readObject()).getPrivateKeyInfo());
        } catch (Exception e) {
            throw new RuntimeException("Unable to Read Signing Private Key from given path: " + signPrivKeyPath, e);
        }

        try {
            PEMParser parser = new PEMParser(new FileReader(signCertPath));
            signCert = new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) parser.readObject());
        } catch (Exception e) {
            throw new RuntimeException("Unable to Read Partner Certificate from given path: " + signCertPath, e);
        }
    }

    public CryptoResponse encryptSign(String request) throws BaseCheckedException {
        CryptoResponse res = new CryptoResponse();
        SecretKey secretKey = symmetrickeyGen.generateKey();

        res.setEncryptedBody(
            Base64.encodeBase64URLSafeString(
                symmetricEncrypt(
                    request.getBytes(),
                    secretKey
                )
            )
        );
        res.setEncryptedKey(
            Base64.encodeBase64URLSafeString(
                asymmetricEncrypt(
                    secretKey.getEncoded()
                )
            )
        );
        res.setHmacDigest(
            Base64.encodeBase64URLSafeString(
                symmetricEncrypt(
                    generateHash(
                        request.getBytes()
                    ).getBytes(),
                    secretKey
                )
            )
        );
        res.setThumbprint(
            encryptCertThumbprint
        );
        return res;
    }

    public String jwtSign(String dataToSign) throws BaseCheckedException {
        JsonWebSignature jwSign = new JsonWebSignature();
        jwSign.setCertificateChainHeaderValue(signCert);
        jwSign.setPayload(dataToSign);
        jwSign.setAlgorithmHeaderValue(signAlgoName);
        jwSign.setKey(signPrivKey);
        jwSign.setDoKeyValidation(false);

        try {
            return jwSign.getDetachedContentCompactSerialization();
        } catch (JoseException e) {
            throw new BaseCheckedException(SIGNATURE_FAILURE_CODE,SIGNATURE_FAILURE_MESSAGE,e);
        }
    }

    private byte[] symmetricEncrypt(byte[] input, SecretKey secretKey) throws BaseCheckedException{
        try{
            Cipher cipher = Cipher.getInstance(symmetricAlgoName);
            byte[] randomIV = generateIV(cipher.getBlockSize());
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(Integer.parseInt(symmetricGcmTagLength), randomIV);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
            return combineByteArrays(cipher.doFinal(input),randomIV);
        } catch(Exception e) {
            throw new BaseCheckedException(SYMMETRIC_ENCRYPT_FAILURE_CODE,SYMMETRIC_ENCRYPT_FAILURE_MESSAGE,e);
        }
    }

    public byte[] asymmetricEncrypt(byte[] input) throws BaseCheckedException{
        try{
            return asymmetricEncryptCipher.doFinal(input);
        } catch(Exception e) {
            throw new BaseCheckedException(ASYMMETRIC_ENCRYPT_FAILURE_CODE,ASYMMETRIC_ENCRYPT_FAILURE_MESSAGE,e);
        }
    }

    private String generateHash(byte[] input) throws BaseCheckedException{
        try{
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            return Hex.encodeHexString(messageDigest.digest(input)).toUpperCase();
        } catch (Exception e) {
            throw new BaseCheckedException(DIGEST_ENCRYPT_FAILURE_CODE,DIGEST_ENCRYPT_FAILURE_MESSAGE,e);
        }
    }

    private byte[] generateIV(int blockSize){
        byte[] byteIV = new byte[blockSize];
        secureRandom.nextBytes(byteIV);
        return byteIV;
    }

    private byte[] combineByteArrays(byte[]... arrays){
        int totalSize = 0;
        for(byte[] array: arrays){
            totalSize+=array.length;
        }
        byte[] output = new byte[totalSize];
        int carry = 0;
        for(byte[] array: arrays){
            System.arraycopy(array,0, output, carry, array.length);
            carry += array.length;
        }
        return output;
    }
}
