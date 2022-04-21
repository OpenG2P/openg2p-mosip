package io.mosip.openg2p.mediator.controller;

import io.mosip.openg2p.mediator.service.DemoAuthService;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    @Autowired
    private DemoAuthService demoAuthService;

    @GetMapping("/ping")
    public String ping() {
        return "ok";
    }

    @PostMapping(value = "/demoAuth", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public String postdemoAuth(@RequestBody String request) {
        return demoAuthService.authenticate(request);
    }
}
