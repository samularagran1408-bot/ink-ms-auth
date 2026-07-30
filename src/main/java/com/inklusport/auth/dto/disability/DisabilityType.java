package com.inklusport.auth.dto.disability;

import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Catálogo canónico de tipos de discapacidad reconocidos en el registro.
 * Acepta alias comunes (p. ej. "fisica" → MOTRIZ) para una UX inclusiva.
 */
public enum DisabilityType {

    MOTRIZ,
    AUDITIVA,
    VISUAL,
    COGNITIVA,
    INTELECTUAL,
    MULTIPLE;

    private static final Map<String, DisabilityType> ALIASES = Map.ofEntries(
            Map.entry("MOTRIZ", MOTRIZ),
            Map.entry("FISICA", MOTRIZ),
            Map.entry("FISICA_MOTORA", MOTRIZ),
            Map.entry("MOTORA", MOTRIZ),
            Map.entry("PHYSICAL", MOTRIZ),
            Map.entry("AUDITIVA", AUDITIVA),
            Map.entry("AUDITORY", AUDITIVA),
            Map.entry("HEARING", AUDITIVA),
            Map.entry("SORDA", AUDITIVA),
            Map.entry("SORDO", AUDITIVA),
            Map.entry("VISUAL", VISUAL),
            Map.entry("VISION", VISUAL),
            Map.entry("COGNITIVA", COGNITIVA),
            Map.entry("COGNITIVE", COGNITIVA),
            Map.entry("INTELECTUAL", INTELECTUAL),
            Map.entry("INTELLECTUAL", INTELECTUAL),
            Map.entry("MULTIPLE", MULTIPLE),
            Map.entry("MULTIPLE_DISABILITY", MULTIPLE)
    );

    public static final Set<String> ALLOWED_VALUES = Arrays.stream(values())
            .map(Enum::name)
            .collect(Collectors.toUnmodifiableSet());

    public boolean requiresCompanion() {
        return this == MOTRIZ;
    }

    /**
     * Resuelve un valor libre (UI o API) al tipo canónico.
     */
    public static Optional<DisabilityType> parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return Optional.empty();
        }
        String normalized = raw.trim()
                .toUpperCase(Locale.ROOT)
                .replace('-', '_')
                .replace(' ', '_');
        DisabilityType type = ALIASES.get(normalized);
        if (type != null) {
            return Optional.of(type);
        }
        try {
            return Optional.of(DisabilityType.valueOf(normalized));
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
    }
}
