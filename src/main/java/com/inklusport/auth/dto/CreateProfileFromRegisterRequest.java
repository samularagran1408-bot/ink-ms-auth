package com.inklusport.auth.dto;

import lombok.Builder;
import lombok.Data;

/**
 * Payload interno auth → users para materializar el perfil al registrarse.
 */
@Data
@Builder
public class CreateProfileFromRegisterRequest {

    private String email;
    private String fullName;
    private String disability;
    private String companionFullName;
    private String companionPhone;
    private String companionRelationship;
    private String companionEmail;
    private String supportPreference;
    private String supportPreferenceNotes;
}
