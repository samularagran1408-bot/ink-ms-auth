package com.inklusport.auth.config;

public class EmailAlreadyRegisteredException extends RuntimeException {

  public EmailAlreadyRegisteredException(String email) {
    super("El correo ya está registrado: " + email);
  }
}
