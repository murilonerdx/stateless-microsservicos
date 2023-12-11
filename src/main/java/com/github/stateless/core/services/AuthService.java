package com.github.stateless.core.services;

import com.github.stateless.core.dto.AuthRequest;
import com.github.stateless.core.dto.TokenDTO;
import com.github.stateless.core.model.User;
import com.github.stateless.core.repository.UserRepository;
import com.github.stateless.infra.AuthenticationException;
import com.github.stateless.infra.ValidationException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;

import static org.springframework.util.ObjectUtils.isEmpty;

@Service
@AllArgsConstructor
public class AuthService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public TokenDTO login(AuthRequest request) {
        User user = repository
                .findByUsername(request.username())
                .orElseThrow(() -> new ValidationException("User not found!"));
        validatePassword(request.password(), user.getPassword());
        var accessToken = jwtService.createToken(user);
        return new TokenDTO(accessToken);
    }



    private void validatePassword(String rawPassword, String encodedPassword) {
        if (!passwordEncoder.matches(rawPassword, encodedPassword)) {
            throw new ValidationException("The password is incorrect!");
        }
    }

    public TokenDTO validateToken(String accessToken) throws AuthenticationException {
        validateExistingToken(accessToken);
        jwtService.validateAccessToken(accessToken);
        return new TokenDTO(accessToken);
    }

    private void validateExistingToken(String accessToken) {
        if (isEmpty(accessToken)) {
            throw new ValidationException("The access token must be informed!");
        }
    }
}