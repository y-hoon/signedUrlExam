package kr.digitcom.signedurlexam.manager;

import com.amazonaws.services.cloudfront.CloudFrontCookieSigner;
import com.amazonaws.services.cloudfront.util.SignerUtils;
import lombok.extern.slf4j.Slf4j;
import org.jets3t.service.CloudFrontService;
import org.jets3t.service.CloudFrontServiceException;
import org.jets3t.service.utils.ServiceUtils;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

@Slf4j
@Component
public class CloudFrontManager {

    /* 사전작업
     * SecretAccess pem key를 아래 명령어로 DER 파일로 변환시킨 후 privateKeyFilePath 경로에 추가한다.
     * openssl pkcs8 -topk8 -nocrypt -in origin.pem -inform PEM -out new.der -outform DER
     */

    private final String distributionDomain = "distribution_Domain";
    private final String privateKeyFilePath = "der 파일 위치";
    private final String s3ObjectKey = "1.png";
    private final String policyResourcePath = "http://" + distributionDomain + "/" + s3ObjectKey;
    private final String keyPairId = ""; // CF KeyPair Id

    private byte[] derPrivateKey;

    public CloudFrontManager() throws IOException {
        derPrivateKey = ServiceUtils.readInputStreamToBytes(new FileInputStream(privateKeyFilePath));
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    // 미리 준비된 정책
    public String createSignedUrlCanned() throws ParseException, CloudFrontServiceException {

        String signedUrlCanned = CloudFrontService.signUrlCanned(
                policyResourcePath, // Resource URL or Path
                keyPairId,     // Certificate identifier,
                derPrivateKey, // DER Private key data
                ServiceUtils.parseIso8601Date("2020-11-14T22:20:00.000Z") // DateLessThan
        );
        log.info("Signed Url Canned ====================== {} =========================", signedUrlCanned);

        return signedUrlCanned;
    }

    public String createCustomSingedUrl() throws ParseException, CloudFrontServiceException {

        String policy = CloudFrontService.buildPolicyForSignedUrl(
                // Resource path (optional, can include '*' and '?' wildcards)
                policyResourcePath,
                // DateLessThan
                // 접근 만료시간 세팅
                ServiceUtils.parseIso8601Date("2011-11-14T22:20:00.000Z"),
                // CIDR IP address restriction (optional, 0.0.0.0/0 means everyone)
                "0.0.0.0/0",
                // DateGreaterThan (optional)
                ServiceUtils.parseIso8601Date("2011-10-16T06:31:56.000Z")
        );

        // Generate a signed URL using a custom policy document.

        String signedUrl = CloudFrontService.signUrl(
                // Resource URL or Path
                "http://" + distributionDomain + "/" + s3ObjectKey,
                // Certificate identifier, an active trusted signer for the distribution
                keyPairId,
                // DER Private key data
                derPrivateKey,
                // Access control policy
                policy
        );

        log.info("Signed Url By Custom Policy ====================== {} =========================", signedUrl);

        return signedUrl;

    }


    public void getCloudFrontCookieForCannedPolicy() throws ParseException, InvalidKeySpecException, IOException {

        CloudFrontCookieSigner.CookiesForCannedPolicy cookies = CloudFrontCookieSigner.getCookiesForCannedPolicy(
                SignerUtils.Protocol.http, distributionDomain, new File(privateKeyFilePath), s3ObjectKey,
                keyPairId,  ServiceUtils.parseIso8601Date("2011-11-14T22:20:00.000Z"));
        // 아래 세개의 값을 세팅한다
        /*
        httpGet.addHeader("Cookie", cookiesForCannedPolicy.getExpires().getKey() + "=" +
                cookies.getExpires().getValue());
        httpGet.addHeader("Cookie", cookiesForCannedPolicy.getSignature().getKey() + "=" +
                cookies.getSignature().getValue());
        httpGet.addHeader("Cookie", cookiesForCannedPolicy.getKeyPairId().getKey() + "=" +
                cookies.getKeyPairId().getValue());
        */
    }

}
