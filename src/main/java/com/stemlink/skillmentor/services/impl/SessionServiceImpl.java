package com.stemlink.skillmentor.services.impl;

import com.stemlink.skillmentor.SkillmentorApplication;
import com.stemlink.skillmentor.entities.Session;
import com.stemlink.skillmentor.entities.Student;
import com.stemlink.skillmentor.entities.Mentor;
import com.stemlink.skillmentor.entities.Subject;
import com.stemlink.skillmentor.exceptions.SkillMentorException;
import com.stemlink.skillmentor.respositories.SessionRepository;
import com.stemlink.skillmentor.respositories.StudentRepository;
import com.stemlink.skillmentor.respositories.MentorRepository;
import com.stemlink.skillmentor.respositories.SubjectRepository;
import com.stemlink.skillmentor.dto.SessionDTO;
import com.stemlink.skillmentor.security.UserPrincipal;
import com.stemlink.skillmentor.services.SessionService;
import com.stemlink.skillmentor.utils.ValidationUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class SessionServiceImpl implements SessionService {

    private final SessionRepository sessionRepository;
    private final StudentRepository studentRepository;
    private final MentorRepository mentorRepository;
    private final SubjectRepository subjectRepository;
    private final ModelMapper modelMapper;

    public Session createNewSession(SessionDTO sessionDTO) {
        // Fetch the related entities by their IDs
        try {
            Student student = studentRepository.findById(sessionDTO.getStudentId()).orElseThrow(
                    () -> new SkillMentorException("Student not found", HttpStatus.NOT_FOUND)
            );
            Mentor mentor = mentorRepository.findByMentorId(String.valueOf(sessionDTO.getMentorId())).orElseThrow(
                    () -> new SkillMentorException("Mentor not found", HttpStatus.NOT_FOUND)
            );
            Subject subject = subjectRepository.findById(sessionDTO.getSubjectId()).orElseThrow(
                    () -> new SkillMentorException("Subject not found", HttpStatus.NOT_FOUND)
            );

            // Checking availability
            ValidationUtils.validateMentorAvailability(mentor, sessionDTO.getSessionAt(), sessionDTO.getDurationMinutes());
            ValidationUtils.validateStudentAvailability(student, sessionDTO.getSessionAt(), sessionDTO.getDurationMinutes());


            // Create and populate the Session entity
//        Session session = new Session();
//        session.setSessionAt(sessionDTO.getSessionAt());
//        session.setDurationMinutes(sessionDTO.getDurationMinutes());
//        session.setSessionStatus(sessionDTO.getSessionStatus());
//        session.setMeetingLink(sessionDTO.getMeetingLink());
//        session.setSessionNotes(sessionDTO.getSessionNotes());
//        session.setStudentReview(sessionDTO.getStudentReview());
//        session.setStudentRating(sessionDTO.getStudentRating());

            // using model mapper
            Session session = modelMapper.map(sessionDTO, Session.class);
            session.setStudent(student);
            session.setMentor(mentor);
            session.setSubject(subject);


            return sessionRepository.save(session);
        } catch (SkillMentorException skillMentorException) {
            log.error("Dependencies not found to map: {}, Failed to create new session", skillMentorException.getMessage());
            throw skillMentorException;
        } catch (Exception exception) {
            log.error("Failed to create session", exception);
            throw new SkillMentorException("Failed to create new session", HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    public List<Session> getAllSessions() {
        return sessionRepository.findAll(); // SELECT * FROM sessions
    }

    public Session getSessionById(Long id) {
        return sessionRepository.findById(id).get();
    }

    public Session updateSessionById(Long id, SessionDTO updatedSessionDTO) {
        Session session = sessionRepository.findById(id).get();

        // source -> destination
        modelMapper.map(updatedSessionDTO, session);

        // Update the related entities
        if (updatedSessionDTO.getStudentId() != null) {
            Student student = studentRepository.findById(updatedSessionDTO.getStudentId()).get();
            session.setStudent(student);
        }
        if (updatedSessionDTO.getMentorId() != null) {
            Mentor mentor = mentorRepository.findByMentorId(String.valueOf(updatedSessionDTO.getMentorId()))
                    .orElseThrow(() -> new SkillMentorException("Mentor not found", HttpStatus.NOT_FOUND));
            session.setMentor(mentor);
        }
        if (updatedSessionDTO.getSubjectId() != null) {
            Subject subject = subjectRepository.findById(updatedSessionDTO.getSubjectId()).get();
            session.setSubject(subject);
        }

//        // Update other fields
//        if (updatedSessionDTO.getSessionAt() != null) {
//            session.setSessionAt(updatedSessionDTO.getSessionAt());
//        }
//        if (updatedSessionDTO.getDurationMinutes() != null) {
//            session.setDurationMinutes(updatedSessionDTO.getDurationMinutes());
//        }
//        if (updatedSessionDTO.getSessionStatus() != null) {
//            session.setSessionStatus(updatedSessionDTO.getSessionStatus());
//        }
//        if (updatedSessionDTO.getMeetingLink() != null) {
//            session.setMeetingLink(updatedSessionDTO.getMeetingLink());
//        }
//        if (updatedSessionDTO.getSessionNotes() != null) {
//            session.setSessionNotes(updatedSessionDTO.getSessionNotes());
//        }
//        if (updatedSessionDTO.getStudentReview() != null) {
//            session.setStudentReview(updatedSessionDTO.getStudentReview());
//        }
//        if (updatedSessionDTO.getStudentRating() != null) {
//            session.setStudentRating(updatedSessionDTO.getStudentRating());
//        }

        return sessionRepository.save(session);
    }

    public void deleteSession(Long id) {
        sessionRepository.deleteById(id);
    }

    public Session enrollSession(UserPrincipal userPrincipal, SessionDTO sessionDTO) {
        // Find student by email from JWT, or auto-create user on first enrollment
        Student student = studentRepository.findByEmail(userPrincipal.getEmail())
                .orElseGet(() -> {
                    Student s = new Student();
                    s.setStudentId(userPrincipal.getId());
                    s.setEmail(userPrincipal.getEmail());
                    s.setFirstName(userPrincipal.getFirstName());
                    s.setLastName(userPrincipal.getLastName());
                    return studentRepository.save(s);
                });

        Mentor mentor = mentorRepository.findByMentorId(String.valueOf(sessionDTO.getMentorId()))
                .orElseThrow(() -> new RuntimeException("Mentor not found with mentorId: " + sessionDTO.getMentorId()));
        Subject subject = subjectRepository.findById(sessionDTO.getSubjectId())
                .orElseThrow(() -> new RuntimeException("Subject not found with id: " + sessionDTO.getSubjectId()));

        Session session = new Session();
        session.setStudent(student);
        session.setMentor(mentor);
        session.setSubject(subject);
        session.setSessionAt(sessionDTO.getSessionAt());
        session.setDurationMinutes(sessionDTO.getDurationMinutes() != null ? sessionDTO.getDurationMinutes() : 60);
        session.setSessionStatus("scheduled");
        session.setPaymentStatus("pending");

        return sessionRepository.save(session);
    }

    public List<Session> getSessionsByStudentEmail(String email) {
        return sessionRepository.findByStudent_Email(email);
    }

}
