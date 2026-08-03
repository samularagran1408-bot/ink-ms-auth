package com.inklusport.auth.validation;

import com.inklusport.auth.dto.CompanionRequest;
import com.inklusport.auth.dto.RegisterRequest;
import com.inklusport.auth.dto.disability.DisabilityType;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.Optional;

/**
 * Reglas de registro inclusivo:
 * <ul>
 *   <li>Discapacidad opcional.</li>
 *   <li>MOTRIZ y AUDITIVA (graves): acompañante obligatorio (nombre + teléfono).</li>
 *   <li>Resto de tipos: acompañante opcional.</li>
 * </ul>
 */
public class DisabilityRegistrationValidator
        implements ConstraintValidator<ValidDisabilityRegistration, RegisterRequest> {

    @Override
    public boolean isValid(RegisterRequest request, ConstraintValidatorContext context) {
        if (request == null) {
            return true;
        }

        context.disableDefaultConstraintViolation();

        String rawType = request.getDisabilityType();
        if (rawType == null || rawType.isBlank()) {
            return validateOptionalCompanion(request.getCompanion(), context);
        }

        Optional<DisabilityType> parsed = DisabilityType.parse(rawType);
        if (parsed.isEmpty()) {
            addViolation(context, "disabilityType",
                    "Tipo de discapacidad no reconocido. Valores admitidos: "
                            + String.join(", ", DisabilityType.ALLOWED_VALUES));
            return false;
        }

        DisabilityType type = parsed.get();
        request.setDisabilityType(type.name());

        boolean valid = true;

        if (type.requiresCompanion() && !hasCompanion(request.getCompanion())) {
            addViolation(context, "companion",
                    "Para discapacidad " + type.name()
                            + " el acompañante es obligatorio. "
                            + "Indique al menos nombre completo y teléfono de contacto.");
            valid = false;
        }

        if (request.getCompanion() != null && !validateOptionalCompanion(request.getCompanion(), context)) {
            valid = false;
        }

        return valid;
    }

    private boolean validateOptionalCompanion(CompanionRequest companion,
                                              ConstraintValidatorContext context) {
        if (companion == null) {
            return true;
        }
        boolean empty = isBlank(companion.getFullName())
                && isBlank(companion.getPhone())
                && isBlank(companion.getRelationship())
                && isBlank(companion.getEmail());
        if (empty) {
            addViolation(context, "companion",
                    "Si registra un acompañante, complete al menos nombre y teléfono.");
            return false;
        }
        return true;
    }

    private boolean hasCompanion(CompanionRequest companion) {
        return companion != null
                && !isBlank(companion.getFullName())
                && !isBlank(companion.getPhone());
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private void addViolation(ConstraintValidatorContext context, String property, String message) {
        context.buildConstraintViolationWithTemplate(message)
                .addPropertyNode(property)
                .addConstraintViolation();
    }
}
