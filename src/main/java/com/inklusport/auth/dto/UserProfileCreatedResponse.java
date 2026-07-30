package com.inklusport.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileCreatedResponse {
    private String id;
    private String email;
    private String fullName;
    private String disability;
}
