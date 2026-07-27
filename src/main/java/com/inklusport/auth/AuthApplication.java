package com.inklusport.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableFeignClients
@EntityScan("com.inklusport.auth.entity")
public class AuthApplication {

  /** Este microservicio funciona */

  public static void main(String[] args) {
      SpringApplication.run(AuthApplication.class, args);
  }
}
