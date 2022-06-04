# Spring-Authorization-Server-0.3.0
Spring Authorization Server 0.3.0

# 说点什么
`Spring Security Oauth2`弃用，`spring-authorization-server`刚刚出来第一版的时候我曾尝鲜过，那时候新版Authorization Server 只有官方demo，还没有使用文档，今天打开Spring.io的时候发现官方的版本更新到了0.3.0，并且提供了说明文档。

![Spring Authorization Server](https://raw.githubusercontent.com/ITLab1024/picgo-images/main/202206032052015.png)

所以打算根据文档尝试下。

# 说明

`Spring Authorization Server` 遵循[Oauth2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05)和[OpenID Connect 1.0，它建立在`Spring Security`之上。

# 最小化项目

## 创建项目

要求JDK11以上

使用Idea创建一个Maven的Spring Boot(笔者使用的是`spring boot 2.7`)项目

pom需要引入`Authorization Server的配置`

```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-authorization-server</artifactId>
    <version>0.3.0</version>
</dependency>
```

完整的pom.xml文件如下：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.7.0</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>io.github.itlab1024</groupId>
    <artifactId>Spring_Authorization_Server_0_3_0</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>Spring-Authorization-Server-0.3.0</name>
    <description>Spring-Authorization-Server-0.3.0</description>
    <properties>
        <java.version>17</java.version>
    </properties>
    <dependencies>
        <!-- 必须引入-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <!-- 必须引入-->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-oauth2-authorization-server</artifactId>
            <version>0.3.0</version>
        </dependency>
        <!-- 必须引入-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <!-- 可选引入-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>
        <!-- 可选引入-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```



## 配置

使用`@Bean`和`@Configuration`创建配置，这是官方推荐的最小配置。

```java
package io.github.itlab1024.base;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * 这是个Spring security 的过滤器链，默认会配置
     * <p>
     * OAuth2 Authorization endpoint
     * <p>
     * OAuth2 Token endpoint
     * <p>
     * OAuth2 Token Introspection endpoint
     * <p>
     * OAuth2 Token Revocation endpoint
     * <p>
     * OAuth2 Authorization Server Metadata endpoint
     * <p>
     * JWK Set endpoint
     * <p>
     * OpenID Connect 1.0 Provider Configuration endpoint
     * <p>
     * OpenID Connect 1.0 UserInfo endpoint
     * 这些协议端点，只有配置了他才能够访问的到接口地址（类似mvc的controller）。
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login"))
                );

        return http.build();
    }

    /**
     * 这个也是个Spring Security的过滤器链，用于Spring Security的身份认证。
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /**
     * 配置用户信息，或者配置用户数据来源，主要用于用户的检索。
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    /**
     * oauth2 用于第三方认证，RegisteredClientRepository 主要用于管理第三方（每个第三方就是一个客户端）
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    /**
     * 用于给access_token签名使用。
     * @return
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * 生成秘钥对，为jwkSource提供服务。
     * @return
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * 配置Authorization Server实例
     * @return
     */
    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().build();
    }
}

```

至此最小化项目完成，这就能够完成oauth2的授权。

## 测试

### 授权码模式

浏览器访问   http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=messaging-client&scope=message.read&redirect_uri=http://127.0.0.1:8080/authorized

> 需要注意的是`redirect_uri`必须是`RegisteredClient`实例设置的。

![授权码模式登录界面](https://raw.githubusercontent.com/ITLab1024/picgo-images/main/202206041338488.png)

输入用户名(user)密码(password）后

![授权界面](https://raw.githubusercontent.com/ITLab1024/picgo-images/main/202206041340559.png)



提交后，会自动跳转到`redirect_uri`地址，并且地址会紧跟着`code`。

![redirect_uri回调后携带code字段](https://raw.githubusercontent.com/ITLab1024/picgo-images/main/202206041426391.png)



返回的code是

```tex
axia5-kuIIzO1D1eu1V_02KawWIkRydiZrDEPAtLhNlYC7kLeUazD_bh5UXGQVJj7W2gxC1zpQJuQ2D9ZVrQyVfufxMYyv4fkjjMitiQ1gH-bGQ6KqGy5egeC15NfHBt
```

接下来需要使用这个`code`获取token（我用postman请求）。

#### 获取token

授权码获取token的请求地址是`oauth2/token`，post请求：

![请求体](https://raw.githubusercontent.com/ITLab1024/picgo-images/main/202206041427997.png)

上线这个三个参数是必须的，并且要跟代码中设置完全一直，另外获取token要传递client_id和client_secret参数，默认不支持使用表单传递，要通过header传递。比如在postman中

![通过header传递client_id和client_secret](https://raw.githubusercontent.com/ITLab1024/picgo-images/main/202206041429370.png)

其实上线的操作实际上就是在header中传递了一个header，key=Authorization， value是client_id:client_secret，然后使用base64加密的字符串,然后前面加上`Basic `(注意后面有空格)。对于我这个例子来说就是`Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=`

返回结果是：

```json
{
    "access_token": "eyJraWQiOiIxNGMxOTM5Yy02YzcxLTQ1MGMtOTg4OS1jOTdiNjM5NTE3ZmEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsIm5iZiI6MTY1NDMyMzg0OSwic2NvcGUiOlsibWVzc2FnZS5yZWFkIl0sImlzcyI6Imh0dHA6XC9cLzEyNy4wLjAuMTo4MDgwIiwiZXhwIjoxNjU0MzI0MTQ5LCJpYXQiOjE2NTQzMjM4NDl9.r6KSDrVbd65n_KRC2SnOH93nGYnoP2uWZwyiamke5PGWa72OHPxgwktgAxK0gHIjQ_sgh5tD4R2swb9bARIn2ZvUb3DtIXpLzEoCGRu4DqJoaUFnj71oAvX1MSruHeLqQaCwL2nJ-C-TNwj_mFHzcZFdaFZRQIIIkaG46Zgj1G0BCxpKtJy3FVIcbGJK-HYHHdh2XOMAIyCA5MrDn2VtZmJDwSbhSSEdU8jY8n41LPUd79koozIH_6onrx-y9ly3-evV3cAGBvsWA26h6PAR0Nxv47LXaUM5Hn_6OA20noCi53CC0qdahRJSs9eHpXsLd0rpjPDrk4nK9S7G0wTIlw",
    "refresh_token": "2CvlhRXdg6EK0ZzS_3kI-AI-AeCXBFpvD1krSbu28sTundjXnwvZT4AuQ03rtUr5TD2VFUWyuAJ68fAmNIonUVSRaDKzdx-Z2Z61np_HlcBF2iUxLRyl4JW9jeBQ7CZG",
    "scope": "message.read",
    "token_type": "Bearer",
    "expires_in": 299
}
```

#### 刷新token

![刷新token请求方式](https://raw.githubusercontent.com/ITLab1024/picgo-images/main/202206041437225.png)

结果是：

```json
{
    "access_token": "eyJraWQiOiIxNGMxOTM5Yy02YzcxLTQ1MGMtOTg4OS1jOTdiNjM5NTE3ZmEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsIm5iZiI6MTY1NDMyNDU1OCwic2NvcGUiOlsibWVzc2FnZS5yZWFkIl0sImlzcyI6Imh0dHA6XC9cLzEyNy4wLjAuMTo4MDgwIiwiZXhwIjoxNjU0MzI0ODU4LCJpYXQiOjE2NTQzMjQ1NTh9.pOsWaoBrNrJyGTYOyvlN1d4FrKjpo2PxRIi7SHLfYjQ0xuqnuYaqPVOhs8rw9VN1hhjpl1d59RixOXkOAIK6PUI_-y_6MTmXL71YZ1lmrifhZ24bYkqXQKMAsbFvj3bXn6RyVnTwFsiy9IzZBRK_-PTPWQd9DbaYkmpryeZtGBqUFYAyBDrgCTYgw0SEoDI2qEX_W3Bgxiz9yTDH5Gszdbe0CzxvHP7LOGDi7-q-WziGhQCoMfFMK0P2WvzeAagseUEUpoSJTk8IMh-_8EgatrwilSYjkKKwgf_-hd9UXDi4bsW9MNA9iIDCYqKJ5dflTutoUJX8oxpnYTwP8iGNDA",
    "refresh_token": "2CvlhRXdg6EK0ZzS_3kI-AI-AeCXBFpvD1krSbu28sTundjXnwvZT4AuQ03rtUr5TD2VFUWyuAJ68fAmNIonUVSRaDKzdx-Z2Z61np_HlcBF2iUxLRyl4JW9jeBQ7CZG",
    "scope": "message.read",
    "token_type": "Bearer",
    "expires_in": 299
}
```

### 简化模式

在oauth2.1中被移除







### 客户端模式

#### 获取token

![客户端模式获取access_token](https://raw.githubusercontent.com/ITLab1024/picgo-images/main/202206041440053.png)

结果是：

```json
{
    "access_token": "eyJraWQiOiIxNGMxOTM5Yy02YzcxLTQ1MGMtOTg4OS1jOTdiNjM5NTE3ZmEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZXNzYWdpbmctY2xpZW50IiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsIm5iZiI6MTY1NDMyNDc5Nywic2NvcGUiOlsib3BlbmlkIiwibWVzc2FnZS5yZWFkIiwibWVzc2FnZS53cml0ZSJdLCJpc3MiOiJodHRwOlwvXC8xMjcuMC4wLjE6ODA4MCIsImV4cCI6MTY1NDMyNTA5NywiaWF0IjoxNjU0MzI0Nzk3fQ.CMWqUxhjOlYzg6SY5uKkWIQDy96XV559TmG2YHZYlwe08a6u7xrwEm_b9m3rd9-QqkQpuxbFBD_o4dk3wl7PKVlZuWNCVrcvEXMFREexU6wwKtzTWKTBWYtDOAvKJN81iJ34UqsXRQ_M3xvUlpVXMjFKY9c3hsP9te8FpfcMi4IZfnHS79CunTh7tgovEo53nu9UNQ2qKy_MR9a13cXpe_AepOP_68gaLO-SAdRI-H9L4e57Y3w7Lq-UWUxywtnAtEcnm_PTGaA-gIEvCiN0rx6pZFBOxv-58OhNfp79oTN33yBDN-E3dSWgioQDp-Sc7kIb8z-rzXa1ZQgx19xTGg",
    "scope": "openid message.read message.write",
    "token_type": "Bearer",
    "expires_in": 299
}
```



客户端模式没有刷新token模式。



### 密码模式

在oauth2.1中被移除

> 以上是最小化示例，我上传到了github，地址是：https://github.com/ITLab1024/Spring-Authorization-Server-0.3.0， 标签是：v1.0.0



# 配置

之前已经通过最小配置，完成了一个`Spring Authorization Server`项目，本章学习下关于配置的内容。

`Spring Authorization Server`还提供了一种实现最小配置的默认配置形式。就是通过`OAuth2AuthorizationServerConfiguration`这个类。

看下这个类的源码：

```java
/*
 * Copyright 2020-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configuration;

import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * {@link Configuration} for OAuth 2.0 Authorization Server support.
 *
 * @author Joe Grandja
 * @since 0.0.1
 * @see OAuth2AuthorizationServerConfigurer
 */
@Configuration(proxyBeanMethods = false)
public class OAuth2AuthorizationServerConfiguration {

   @Bean
   @Order(Ordered.HIGHEST_PRECEDENCE)
   public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
      applyDefaultSecurity(http);
      return http.build();
   }

   // @formatter:off
   public static void applyDefaultSecurity(HttpSecurity http) throws Exception {
      OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
            new OAuth2AuthorizationServerConfigurer<>();
      RequestMatcher endpointsMatcher = authorizationServerConfigurer
            .getEndpointsMatcher();

      http
         .requestMatcher(endpointsMatcher)
         .authorizeRequests(authorizeRequests ->
            authorizeRequests.anyRequest().authenticated()
         )
         .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
         .apply(authorizationServerConfigurer);
   }
   // @formatter:on

   public static JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
      Set<JWSAlgorithm> jwsAlgs = new HashSet<>();
      jwsAlgs.addAll(JWSAlgorithm.Family.RSA);
      jwsAlgs.addAll(JWSAlgorithm.Family.EC);
      jwsAlgs.addAll(JWSAlgorithm.Family.HMAC_SHA);
      ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
      JWSKeySelector<SecurityContext> jwsKeySelector =
            new JWSVerificationKeySelector<>(jwsAlgs, jwkSource);
      jwtProcessor.setJWSKeySelector(jwsKeySelector);
      // Override the default Nimbus claims set verifier as NimbusJwtDecoder handles it instead
      jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
      });
      return new NimbusJwtDecoder(jwtProcessor);
   }

   @Bean
   RegisterMissingBeanPostProcessor registerMissingBeanPostProcessor() {
      RegisterMissingBeanPostProcessor postProcessor = new RegisterMissingBeanPostProcessor();
      postProcessor.addBeanDefinition(ProviderSettings.class, () -> ProviderSettings.builder().build());
      return postProcessor;
   }

}
```

这里注入一个叫做`authorizationServerSecurityFilterChain`的bean，这跟我之前最小化项目时实现的基本是相同的。

有了这个bean，就会支持如下协议端点：

- [OAuth2 Authorization endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-authorization-endpoint)
- [OAuth2 Token endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-token-endpoint)
- [OAuth2 Token Introspection endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-token-introspection-endpoint)
- [OAuth2 Token Revocation endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-token-revocation-endpoint)
- [OAuth2 Authorization Server Metadata endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-authorization-server-metadata-endpoint)
- [JWK Set endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#jwk-set-endpoint)
- [OpenID Connect 1.0 Provider Configuration endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oidc-provider-configuration-endpoint)
- [OpenID Connect 1.0 UserInfo endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oidc-user-info-endpoint)

接来我我尝试使用`OAuth2AuthorizationServerConfiguration`这个类来实现一个`Authorization Server`。

> 本次我会将 Spring Security和Authorization Server的配置分开

Spring Security 使用 `SecurityConfig`  类，创建一个新的`Authorization Server`配置类 `AuthorizationServerConfig`。



SecurityConfig类配置如下：

```java
package io.github.itlab1024.base;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    /**
     * 这个也是个Spring Security的过滤器链，用于Spring Security的身份认证。
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /**
     * 配置用户信息，或者配置用户数据来源，主要用于用户的检索。
     *
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }
}
```

代码如下：

```java
package io.github.itlab1024.base;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig {

    /**
     * oauth2 用于第三方认证，RegisteredClientRepository 主要用于管理第三方（每个第三方就是一个客户端）
     *
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    /**
     * 用于给access_token签名使用。
     *
     * @return
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * 生成秘钥对，为jwkSource提供服务。
     *
     * @return
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
}
```

至此可以实现了`Authorization Server`。

测试客户端调用。

![客户端模式](/Users/shizhenchao/Library/Application Support/typora-user-images/image-20220604192515635.png)

授权码模式测试

![授权码模式](https://raw.githubusercontent.com/ITLab1024/picgo-images/main/202206042117755.png)



![获取code](https://raw.githubusercontent.com/ITLab1024/picgo-images/main/202206042118989.png)



![授权码模式-获取token](https://raw.githubusercontent.com/ITLab1024/picgo-images/main/202206042121444.png)

授权码模式也没有问题。

> 提交分支 v2.0.0
