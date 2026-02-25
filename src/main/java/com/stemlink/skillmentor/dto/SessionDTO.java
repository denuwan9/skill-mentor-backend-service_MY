package com.stemlink.skillmentor.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Min;
import lombok.Data;

import java.util.Date;

@Data
public class SessionDTO {

    @NotNull(message = "Student ID cannot be null")
    private Integer studentId;

    @NotNull(message = "Mentor ID cannot be null")
    private Long mentorId;

    @NotNull(message = "Subject ID cannot be null")
    private Long subjectId;

    @NotNull(message = "Session date/time cannot be null")
    private Date sessionAt;

    @Min(value = 1, message = "Duration must be at least 1 minute")
    private Integer durationMinutes;

    private String sessionStatus;

    private String meetingLink;

    private String sessionNotes;

    private String studentReview;

    @Min(value = 1, message = "Rating must be at least 1")
    private Integer studentRating;

    private String paymentStatus;

}
