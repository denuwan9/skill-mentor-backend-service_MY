package com.stemlink.skillmentor.controllers;


import com.stemlink.skillmentor.dto.StudentDTO;
import com.stemlink.skillmentor.entities.Student;
import com.stemlink.skillmentor.services.StudentService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import com.stemlink.skillmentor.security.UserPrincipal;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

import java.util.List;

import static com.stemlink.skillmentor.constants.UserRoles.*;

@RestController
@RequestMapping(path = "/api/v1/students")
@RequiredArgsConstructor
@Validated
@PreAuthorize("isAuthenticated()")
public class StudentController extends AbstractController{

    private final StudentService studentService;
    private final ModelMapper modelMapper;

    @GetMapping
    public ResponseEntity<List<Student>> getAllStudents() {
        List<Student> students = studentService.getAllStudents();
        return sendOkResponse(students);
    }

    @GetMapping("{id}")
    public ResponseEntity<Student> getStudentById(@PathVariable Integer id) {
        Student student = studentService.getStudentById(id);
        return sendOkResponse(student);
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_STUDENT + "')")
    public ResponseEntity<Student> createStudent(@Valid @RequestBody StudentDTO studentDTO, Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        Student student = modelMapper.map(studentDTO, Student.class);
        student.setStudentId(userPrincipal.getId());
        student.setFirstName(userPrincipal.getFirstName());
        student.setLastName(userPrincipal.getLastName());
        student.setEmail(userPrincipal.getEmail());

        Student createdStudent = studentService.createNewStudent(student);
        return sendCreatedResponse(createdStudent);
    }

    @PutMapping("{id}")
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "', '" + ROLE_STUDENT + "')")
    public ResponseEntity<Student> updateStudent(@PathVariable Integer id, @Valid @RequestBody StudentDTO updatedStudentDTO) {
        Student student = modelMapper.map(updatedStudentDTO, Student.class);
        Student updatedStudent = studentService.updateStudentById(id, student);
        return sendOkResponse(updatedStudent);
    }

    @DeleteMapping("{id}")
    @PreAuthorize("hasAnyRole('" + ROLE_ADMIN + "')")
    public ResponseEntity<Void> deleteStudent(@PathVariable Integer id) {
        studentService.deleteStudent(id);
        return sendNoContentResponse();
    }
}
