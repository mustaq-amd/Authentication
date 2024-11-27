package com.rbac.auth.dto;

import lombok.Data;

@Data
public class OtpRequest {

    private String email;   // Optional
    private String mobile;  // Optional
    private String otp;
}
