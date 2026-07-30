package com.inklusport.auth.dto.disability;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Preferencias de apoyo comunicativo para discapacidad auditiva.
 * El acompañante no es obligatorio; sí lo es declarar cómo prefiere recibir apoyo.
 */
public enum SupportPreference {

    INTERPRETE_LENGUA_SENAS,
    LECTURA_LABIAL,
    SUBTITULOS,
    TRANSCRIPCION_TIEMPO_REAL,
    APOYO_VISUAL_ESCRITO,
    OTRO;

    public static final Set<String> ALLOWED_VALUES = Arrays.stream(values())
            .map(Enum::name)
            .collect(Collectors.toUnmodifiableSet());

    public static Optional<SupportPreference> parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        String normalized = raw.trim()
                .toUpperCase(Locale.ROOT)
                .replace('-', '_')
                .replace(' ', '_');
        try {
            return Optional.of(SupportPreference.valueOf(normalized));
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }
}
