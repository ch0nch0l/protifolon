package com.choncholsgarbage.protifolon.controller;


import com.choncholsgarbage.protifolon.enums.RoleName;
import com.choncholsgarbage.protifolon.message.request.LoginRequest;
import com.choncholsgarbage.protifolon.message.request.SignUpRequest;
import com.choncholsgarbage.protifolon.message.response.JwtResponse;
import com.choncholsgarbage.protifolon.model.Role;
import com.choncholsgarbage.protifolon.model.User;
import com.choncholsgarbage.protifolon.repository.RoleRepository;
import com.choncholsgarbage.protifolon.repository.UserRepository;
import com.choncholsgarbage.protifolon.security.jwt.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Set;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtProvider jwtProvider;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest){

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtProvider.generateJwtToken(authentication);
        return ResponseEntity.ok(new JwtResponse(jwt));
    }

    @PostMapping("/signup")
    public ResponseEntity<String> registerUser(@Valid @RequestBody SignUpRequest signUpRequest){

        if (userRepository.existsByUsername(signUpRequest.getUsername())){
            return new ResponseEntity<String>("Registration Failed! Username Already taken.!", HttpStatus.BAD_REQUEST);
        }

        User user = new User(signUpRequest.getName(), signUpRequest.getUsername(),
                signUpRequest.getEmail(), passwordEncoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        strRoles.forEach(role ->{

            switch (role){
                case "admin":
                    Role adminRole = roleRepository.findByRoleName(RoleName.ROLE_ADMIN)
                            .orElseThrow(()-> new RuntimeException("Failed! Cause: User Role not found."));

                    roles.add(adminRole);

                    break;

                case "customer":
                    Role customerRole = roleRepository.findByRoleName(RoleName.ROLE_CUSTOMER)
                            .orElseThrow(()-> new RuntimeException("Failed! Cause: User Role not found."));

                    roles.add(customerRole);

                    break;

                case "merchant":
                    Role merchantRole = roleRepository.findByRoleName(RoleName.ROLE_MERCHANT)
                            .orElseThrow(()-> new RuntimeException("Failed! Cause: User Role not found."));

                    roles.add(merchantRole);

                    break;

                 default:
                     Role userRole = roleRepository.findByRoleName(RoleName.ROLE_USER)
                             .orElseThrow(() -> new RuntimeException("Failed! Cause: User Role not found."));
                     roles.add(userRole);
            }
        });

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok().body("User Registration Successful!");
    }
}
