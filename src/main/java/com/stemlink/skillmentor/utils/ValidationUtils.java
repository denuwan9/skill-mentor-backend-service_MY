package com.stemlink.skillmentor.utils;

import com.stemlink.skillmentor.entities.Mentor;
import com.stemlink.skillmentor.entities.Session;
import com.stemlink.skillmentor.entities.Student;
import com.stemlink.skillmentor.exceptions.SkillMentorException;
import org.springframework.http.HttpStatus;

import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class ValidationUtils {

    /**
     * Validates if the mentor is available during the requested session time
     * @param mentor The mentor entity
     * @param sessionAt The session start time
     * @param durationMinutes The session duration in minutes
     * @throws IllegalArgumentException if mentor is not available
     */
    public static void validateMentorAvailability(Mentor mentor, Date sessionAt, Integer durationMinutes) {
        if (durationMinutes == null || durationMinutes <= 0) {
            durationMinutes = 60; // default duration
        }

        Date sessionEnd = addMinutesToDate(sessionAt, durationMinutes);
        List<Session> mentorSessions = mentor.getSessions();

        for (Session existingSession : mentorSessions) {
            Date existingStart = existingSession.getSessionAt();
            Date existingEnd = addMinutesToDate(existingStart, existingSession.getDurationMinutes());

            // Check for time overlap
            if (isTimeOverlap(sessionAt, sessionEnd, existingStart, existingEnd)) {
                throw new SkillMentorException("Mentor is not available at the requested time", HttpStatus.CONFLICT);
            }
        }
    }

    /**
     * Validates if the student is available during the requested session time
     * @param student The student entity
     * @param sessionAt The session start time
     * @param durationMinutes The session duration in minutes
     * @throws IllegalArgumentException if student is not available
     */
    public static void validateStudentAvailability(Student student, Date sessionAt, Integer durationMinutes) {
        if (durationMinutes == null || durationMinutes <= 0) {
            durationMinutes = 60; // default duration
        }

        Date sessionEnd = addMinutesToDate(sessionAt, durationMinutes);
        List<Session> studentSessions = student.getSessions();

        for (Session existingSession : studentSessions) {
            Date existingStart = existingSession.getSessionAt();
            Date existingEnd = addMinutesToDate(existingStart, existingSession.getDurationMinutes());

            // Check for time overlap
            if (isTimeOverlap(sessionAt, sessionEnd, existingStart, existingEnd)) {
                throw new SkillMentorException("Student is not available at the requested time", HttpStatus.CONFLICT);
            }
        }
    }

    /**
     * Checks if two time periods overlap
     */
    public static boolean isTimeOverlap(Date start1, Date end1, Date start2, Date end2) {
        return start1.before(end2) && start2.before(end1);
    }

    /**
     * Adds minutes to a given date
     */
    public static Date addMinutesToDate(Date date, int minutes) {
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.add(Calendar.MINUTE, minutes);
        return calendar.getTime();
    }
}
