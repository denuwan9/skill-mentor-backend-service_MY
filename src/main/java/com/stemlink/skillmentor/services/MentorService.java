package com.stemlink.skillmentor.services;

import com.stemlink.skillmentor.entities.Mentor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface MentorService {
    Mentor createNewMentor(Mentor mentor);
    Page<Mentor> getAllMentors(String name, Pageable pageable);
    Mentor getMentorById(Long id);
    Mentor updateMentorById(Long id, Mentor updatedMentor);
    void deleteMentor(Long id);
}
