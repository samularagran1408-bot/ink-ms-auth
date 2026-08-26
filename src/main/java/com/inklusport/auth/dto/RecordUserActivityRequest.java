package com.inklusport.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RecordUserActivityRequest {
    private String email;
    private String action;
    private String details;
    private String ipAddress;
}
