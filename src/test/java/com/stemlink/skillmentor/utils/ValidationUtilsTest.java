package com.stemlink.skillmentor.utils;

import com.stemlink.skillmentor.entities.Mentor;
import com.stemlink.skillmentor.entities.Session;
import com.stemlink.skillmentor.entities.Student;
import com.stemlink.skillmentor.exceptions.SkillMentorException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class ValidationUtilsTest {

    private Date createDate(int year, int month, int day, int hour, int minute) {
        LocalDateTime ldt = LocalDateTime.of(year, month, day, hour, minute);
        return Date.from(ldt.atZone(ZoneId.systemDefault()).toInstant());
    }

    @Test
    void isTimeOverlap_ReturnsTrue_WhenTimesOverlap() {
        Date start1 = createDate(2023, 1, 1, 10, 0);
        Date end1 = createDate(2023, 1, 1, 11, 0);

        // Overlap: 10:30 - 11:30 overlapping with 10:00 - 11:00
        Date start2 = createDate(2023, 1, 1, 10, 30);
        Date end2 = createDate(2023, 1, 1, 11, 30);

        assertTrue(ValidationUtils.isTimeOverlap(start1, end1, start2, end2));
    }

    @Test
    void isTimeOverlap_ReturnsFalse_WhenTimesDoNotOverlap() {
        Date start1 = createDate(2023, 1, 1, 10, 0);
        Date end1 = createDate(2023, 1, 1, 11, 0);

        // No Overlap: 11:00 - 12:00 (Starting exactly when the first ends)
        // Adjusting logic: start1 < end2 && start2 < end1
        // 10:00 < 12:00 (T) && 11:00 < 11:00 (F) -> False
        Date start2 = createDate(2023, 1, 1, 11, 0);
        Date end2 = createDate(2023, 1, 1, 12, 0);

        assertFalse(ValidationUtils.isTimeOverlap(start1, end1, start2, end2));
    }

    @Test
    void addMinutesToDate_AddsCorrectMinutes() {
        Date start = createDate(2023, 1, 1, 10, 0); // 10:00
        Date expected = createDate(2023, 1, 1, 10, 30); // 10:30

        Date result = ValidationUtils.addMinutesToDate(start, 30);

        assertEquals(expected, result);
    }

    @Test
    void validateMentorAvailability_ThrowsException_WhenOverlapExists() {
        Mentor mentor = new Mentor();
        List<Session> sessions = new ArrayList<>();

        Session existingSession = new Session();
        existingSession.setSessionAt(createDate(2023, 1, 1, 10, 0));
        existingSession.setDurationMinutes(60); // Ends at 11:00
        sessions.add(existingSession);

        mentor.setSessions(sessions);

        Date newSessionAt = createDate(2023, 1, 1, 10, 30); // Starts at 10:30 (overlap)

        assertThrows(SkillMentorException.class, () ->
                ValidationUtils.validateMentorAvailability(mentor, newSessionAt, 60)
        );
    }

    @Test
    void validateMentorAvailability_DoesNotThrow_WhenNoOverlap() {
        Mentor mentor = new Mentor();
        List<Session> sessions = new ArrayList<>();

        Session existingSession = new Session();
        existingSession.setSessionAt(createDate(2023, 1, 1, 10, 0));
        existingSession.setDurationMinutes(60); // Ends at 11:00
        sessions.add(existingSession);

        mentor.setSessions(sessions);

        Date newSessionAt = createDate(2023, 1, 1, 12, 0); // Starts at 12:00 (no overlap)

        assertDoesNotThrow(() ->
                ValidationUtils.validateMentorAvailability(mentor, newSessionAt, 60)
        );
    }

    @Test
    void validateStudentAvailability_ThrowsException_WhenOverlapExists() {
        Student student = new Student();
        List<Session> sessions = new ArrayList<>();

        Session existingSession = new Session();
        existingSession.setSessionAt(createDate(2023, 1, 1, 14, 0));
        existingSession.setDurationMinutes(60); // Ends at 15:00
        sessions.add(existingSession);

        student.setSessions(sessions);

        Date newSessionAt = createDate(2023, 1, 1, 14, 30); // Starts at 14:30 (overlap)

        assertThrows(SkillMentorException.class, () ->
                ValidationUtils.validateStudentAvailability(student, newSessionAt, 60)
        );
    }
}
