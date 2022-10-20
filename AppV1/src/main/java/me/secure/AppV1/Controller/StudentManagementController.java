package me.secure.AppV1.Controller;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import me.secure.AppV1.Entity.Student;

@RestController
@RequestMapping("management/api/students")
public class StudentManagementController {

	private static final List<Student> STUDENTS = Arrays.asList(
			new Student(1, "Abi"),
			new Student(2, "Billa"),
			new Student(3, "Jack"),
			new Student(4, "Faf")
			);

	@GetMapping
	@PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_ADMINTRAINEE')")
	public List<Student> getAllStudents(){
		System.out.println("Gettin all Student");
		return STUDENTS;
	}

	@PostMapping
	@PreAuthorize("hasAuthority('student:write')")
	public void registerNewStudent(@RequestBody Student student)
	{
		System.out.println("Registering a New Student");
		System.out.println(student);
	}

	@DeleteMapping(path = "{studentId}")
	@PreAuthorize("hasAuthority('student:write')")
	public void deleteStudent(@PathVariable("studentId") Integer studentId)
	{
		System.out.println("Deleting an existing Student");
		System.out.println(studentId);
	}

	@PutMapping(path = "{studentId}")
	@PreAuthorize("hasAuthority('student:write')")
	public void updateStudent(@PathVariable("studentId") Integer studentId,@RequestBody Student student)
	{
		System.out.println("Updating an existing Student");
		System.out.println(String.format("%s %s", student,student));
	}
}
