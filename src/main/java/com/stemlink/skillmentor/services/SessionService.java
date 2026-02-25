package com.stemlink.skillmentor.services;

import com.stemlink.skillmentor.dto.SessionDTO;
import com.stemlink.skillmentor.entities.Session;
import com.stemlink.skillmentor.security.UserPrincipal;

import java.util.List;

public interface SessionService {

    Session createNewSession(SessionDTO sessionDTO);
    List<Session> getAllSessions();
    Session getSessionById(Long id);
    Session updateSessionById(Long id, SessionDTO updatedSessionDTO);
    void deleteSession(Long id);

    // Frontend enrollment flow — student is resolved from the Clerk JWT
    Session enrollSession(UserPrincipal userPrincipal, SessionDTO sessionDTO);
    List<Session> getSessionsByStudentEmail(String email);
}
