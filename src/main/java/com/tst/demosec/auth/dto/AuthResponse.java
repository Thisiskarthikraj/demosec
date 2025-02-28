package com.tst.demosec.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.experimental.Accessors;

@Data
@AllArgsConstructor
public class AuthResponse {
    private String message;
    private String SessionId;
}