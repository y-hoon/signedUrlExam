package kr.digitcom.signedurlexam.manager;

import org.jets3t.service.CloudFrontServiceException;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.*;
import org.springframework.web.client.RestTemplate;


import java.io.IOException;
import java.text.ParseException;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class CloudFrontManagerTest {

    CloudFrontManager cloudFrontManager;

    @Before
    public void setUp() throws IOException {
        cloudFrontManager = new CloudFrontManager();
    }

    @Test
    public void createSignedUrlCanned() throws ParseException, CloudFrontServiceException, IOException {
        String signedUrl = cloudFrontManager.createSignedUrlCanned();
        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity responseEntity = restTemplate.exchange(signedUrl, HttpMethod.GET, new HttpEntity<>(new HttpHeaders()), String.class);
        assertThat(responseEntity.getStatusCode(), is(HttpStatus.OK));
    }
}
