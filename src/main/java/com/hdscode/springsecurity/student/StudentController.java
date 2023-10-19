package com.hdscode.springsecurity.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/v1")
public class StudentController {
    private static final List<Student> students = Arrays.asList(
            new Student(1, "luffy"),
            new Student(2, "nami"),
            new Student(3, "zoro")
    );

    @GetMapping("/student/{id}")
    public Student getStudent(@PathVariable("id") Integer id) {
        return students.stream()
                .filter(student -> id.equals(student.getId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Student not found"));
    }
}
