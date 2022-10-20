package me.secure.AppV1.Controller;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import me.secure.AppV1.Entity.Student;

@RestController
@RequestMapping("/api/students")
public class StudentController {

	private static final List<Student> STUDENTS = Arrays.asList(
			new Student(1, "Abi"),
			new Student(2, "Billa"),
			new Student(3, "Jack"),
			new Student(4, "Faf")
			);

	@GetMapping(path ="{StudentId}")
	public Student getStudent(@PathVariable("StudentId") Integer StudentId) {
	return STUDENTS
			.stream()
				.filter(student -> StudentId.equals(student.getStudentId()))
				.findFirst()
				.orElseThrow(()->
				new IllegalStateException("Student "+StudentId+" doesn't exist"));
	}

}
