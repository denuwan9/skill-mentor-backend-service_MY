package com.stemlink.skillmentor.dto;

import jakarta.validation.constraints.*;
import lombok.Data;

@Data
public class SubjectDTO {

    @NotNull(message = "cannot be null")
    @Size(min = 5, message = "Subject must be at least 5 characters long")
    private String subjectName;

    @Size(max = 500, message = "Description must not exceed 500 characters")
    private String description;

    private String courseImageUrl;

    @NotNull
    private Long mentorId;
}
