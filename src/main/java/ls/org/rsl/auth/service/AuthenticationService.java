package ls.org.rsl.auth.service;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

public interface AuthenticationService {
    String createToken(Authentication authentication);
}
