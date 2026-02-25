package com.stemlink.skillmentor.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class MentorDTO {

    // Admin-only override fields — if provided by an ADMIN caller, these are used
    // directly instead of extracting identity from the JWT claims. Ignored for MENTOR role.
    private String mentorId;

    @Size(max = 100, message = "First name must not exceed 100 characters")
    private String firstName;

    @Size(max = 100, message = "Last name must not exceed 100 characters")
    private String lastName;

    @Email(message = "Email must be valid")
    private String email;

    @Size(max = 20, message = "Phone number must not exceed 20 characters")
    private String phoneNumber;

    @Size(max = 100, message = "Title must not exceed 100 characters")
    private String title;

    @Size(max = 100, message = "Profession must not exceed 100 characters")
    private String profession;

    @Size(max = 100, message = "Company must not exceed 100 characters")
    private String company;

    private int experienceYears;

    @Size(max = 500, message = "Bio must not exceed 500 characters")
    private String bio;

    // Additional fields required for frontend mentor profile displays
    private String profileImageUrl;

    private Integer positiveReviews;

    private Integer totalEnrollments;

    private Boolean isCertified;

    @Size(max = 10, message = "Start year must not exceed 10 characters")
    private String startYear;
}
