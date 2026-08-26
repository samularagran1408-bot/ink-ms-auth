package com.inklusport.auth.client;

import com.inklusport.auth.dto.CreateProfileFromRegisterRequest;
import com.inklusport.auth.dto.RecordUserActivityRequest;
import com.inklusport.auth.dto.UserAccessStatusResponse;
import com.inklusport.auth.dto.UserProfileCreatedResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.List;

@FeignClient(
        name = "ink-ms-users",
        url = "${users.service.url}",
        fallback = UserServiceFallback.class
)
public interface UserServiceClient {

    @GetMapping("/api/internal/users/roles-by-email")
    List<String> getUserRoles(@RequestParam("email") String email);

    @GetMapping("/api/internal/users/access-status")
    UserAccessStatusResponse getAccessStatus(@RequestParam("email") String email);

    @PostMapping("/api/internal/users/profile-from-register")
    UserProfileCreatedResponse createProfileFromRegister(@RequestBody CreateProfileFromRegisterRequest request);

    @PostMapping("/api/internal/users/activity")
    void recordActivity(@RequestBody RecordUserActivityRequest request);
}
