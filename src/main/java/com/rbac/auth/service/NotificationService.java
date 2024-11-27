package com.rbac.auth.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class NotificationService {
    private final static Logger LOGGER = LoggerFactory.getLogger(NotificationService.class);

    @Autowired
    private final JavaMailSender mailSender;

    @Async
    public void sendEmailOtp(String email, String otp) {
        /*SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject("Your Login OTP");
        message.setText("Your OTP is: " + otp);
        mailSender.send(message);*/
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper =
                    new MimeMessageHelper(mimeMessage, "utf-8");
            helper.setTo(email);
            helper.setSubject("Your Login OTP");
            helper.setText("Your OTP is: " + otp);
            mailSender.send(mimeMessage);
        } catch (MessagingException e) {
            LOGGER.error("failed to send email", e);
            throw new IllegalStateException("failed to send email");
        }
    }

//    public void sendSmsOtp(String mobile, String otp) {
//        // Replace this with your SMS gateway integration
//        String message = "Your OTP is: " + otp;
//        smsGatewayService.sendSms(mobile, message);
//    }
}
