package com.hdscode.springsecurity.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/student")
public class ManagementStudentController {

    private static final List<Student> students = Arrays.asList(
            new Student(1, "luffy"),
            new Student(2, "nami"),
            new Student(3, "zoro")
    );

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public List<Student> getStudents(){
        return students;
    }

    @PostMapping
    @PreAuthorize("hasAnyAuthority('student:write')")
    public void registerNewStudent(@RequestBody Student student){
        System.out.println("create student : " + student);
    }

    @DeleteMapping(path="{id}")
    @PreAuthorize("hasAnyAuthority('student:write')")
    public void removeStudent(@PathVariable("id") Integer studentId){
        System.out.println("Removing student with id: " + studentId);

    }
    @PutMapping(path = "{id}")
    @PreAuthorize("hasAnyAuthority('student:write')")
    public void updateStudent(@PathVariable("id") Integer studentId, @RequestBody Student student){
        System.out.println("Updating student with id: " + studentId);
        System.out.println("student: " + student);
    }
}
