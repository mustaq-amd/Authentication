package com.rbac.auth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class NotificationService {

    @Autowired
    private final JavaMailSender mailSender;

    public void sendEmailOtp(String email, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Your Login OTP");
        message.setText("Your OTP is: " + otp);
        mailSender.send(message);
    }

//    public void sendSmsOtp(String mobile, String otp) {
//        // Replace this with your SMS gateway integration
//        String message = "Your OTP is: " + otp;
//        smsGatewayService.sendSms(mobile, message);
//    }
}
