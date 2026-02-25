package com.stemlink.skillmentor.respositories;

import com.stemlink.skillmentor.entities.Subject;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SubjectRepository extends JpaRepository<Subject,Long> {

    // custom queries
}
