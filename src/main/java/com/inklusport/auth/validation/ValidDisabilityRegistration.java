package com.inklusport.auth.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Valida las reglas de discapacidad + acompañante + preferencia de apoyo
 * en el registro de forma contextual y respetuosa.
 */
@Documented
@Constraint(validatedBy = DisabilityRegistrationValidator.class)
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidDisabilityRegistration {

    String message() default "Los datos de discapacidad del registro no son válidos";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
