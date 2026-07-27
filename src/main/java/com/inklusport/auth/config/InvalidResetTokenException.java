package com.inklusport.auth.config;

public class InvalidResetTokenException extends RuntimeException {

  public InvalidResetTokenException(String message) {
    super(message);
  }
}
