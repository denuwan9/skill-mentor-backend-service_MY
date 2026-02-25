package com.stemlink.skillmentor.dto;

import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class StudentDTO {

    @Size(max = 500, message = "Learning goals must not exceed 500 characters")
    private String learningGoals;

}
