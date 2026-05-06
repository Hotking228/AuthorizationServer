package com.hotking.config;

import com.hotking.entity.User;
import com.hotking.repository.UserRepository;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
        throws Exception{
        return http.authorizeHttpRequests(requests -> requests
                        .requestMatchers("/login", "/error").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .build();
    }

    @Bean
    UserDetailsService userDetailsService(UserRepository userRepo) {
        return username -> userRepo.findByUsername(username);
    }

    @Bean
    public ApplicationRunner dataLoader(
            UserRepository repo, PasswordEncoder encoder) {
        return args -> {
            repo.save(
                    User.builder()
                            .username("habuma")
                            .password(encoder.encode("password"))
                            .role(User.Role.ROLE_ADMIN)
                            .build());
            repo.save(
                    User.builder()
                            .username("tacochef")
                            .password(encoder.encode("password"))
                            .role(User.Role.ROLE_ADMIN)
                            .build());
        };
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)//этот бин имеет приоритет над другими бинами этого же типа
    public SecurityFilterChain
        authorizationServerFilterChain(HttpSecurity http) throws Exception{
        OAuth2AuthorizationServerConfiguration
                .applyDefaultSecurity(http);
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        return http
                .formLogin(Customizer.withDefaults())
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder encoder){
        RegisteredClient registeredClient =
                RegisteredClient.withId(UUID.randomUUID().toString()) //создаем случайный id клиента
                        .clientId("taco-admin-client")//Аналог имени пользователя
                        .clientSecret(encoder.encode("secret"))//Аналог пароля
                        .clientAuthenticationMethod(
                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)//Типы разрешений oauth2
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUri( //URL, куда сервер переадресует клиента в случае авторизации
                                "https://127.0.0.1:8443/login/oauth2/code/taco-admin-client")
                        .scope("writeIngredients")//Области действия, которые разрешено запрашивать клиенту
                        .scope("deleteIngredients")
                        .scope(OidcScopes.OPENID)
                        .clientSettings(ClientSettings.builder()//Запрашиваем явное согласие пользователя перед предоставлением доступа
                                .requireAuthorizationConsent(true)
                                .build())
                        .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    /*
        Наше приложение создает JWT - JSON Web Token, который служит для предоставления доступа клиенту
    после аутентификации
        JWK - JSON Web Key - ключ для создания подписи для JWT
     */

    /*
        JWT в себе содержит signature - цифровую подпись, которая формируется на сервере(jwk),
       эта сигнатура формируется как условная хеш-функция от данных в самом jwt(payload), разность данных
       обеспечивает временная метка, которая так же обеспечивает время жизни токена, относительно
       сервера авторизации, время на сервере ресурсов и авторизации синхронизировано и когда сервер ресурсов
       проверяет подпись токена он так же проверяет время и получает хеш функцию от данных токена, если
       совпадают полученная сигнатура и сигнатура из jwt -> jwt валидный.
     */

    @Bean
    public JWKSource<SecurityContext> jwkSource()
        throws NoSuchAlgorithmException{
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static RSAKey generateRsa() throws NoSuchAlgorithmException{
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() throws NoSuchAlgorithmException{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource){
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
