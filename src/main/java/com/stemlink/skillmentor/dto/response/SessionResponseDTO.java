package com.stemlink.skillmentor.dto.response;

import lombok.Data;

import java.util.Date;

@Data
public class SessionResponseDTO {
    private Integer id;
    private String mentorName;
    private String mentorProfileImageUrl;
    private String subjectName;
    private Date sessionAt;
    private Integer durationMinutes;
    private String sessionStatus;
    private String paymentStatus;
    private String meetingLink;
}
