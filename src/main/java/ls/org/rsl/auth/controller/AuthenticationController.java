package ls.org.rsl.auth.controller;

import lombok.RequiredArgsConstructor;
import ls.org.rsl.auth.dto.JwtResponse;
import ls.org.rsl.auth.service.Impl.AuthenticationServiceImpl;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1")
public class AuthenticationController {

    private final AuthenticationServiceImpl authenticationService;

    @PostMapping("/auth")
    public JwtResponse authentication(Authentication authentication){
        return new JwtResponse(authenticationService.createToken(authentication));
    }

    @GetMapping("/hello")
    public String hello(){
        return "Hello, welcome to the system";
    }
}
