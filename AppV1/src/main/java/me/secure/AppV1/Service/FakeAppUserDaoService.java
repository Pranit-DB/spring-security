package me.secure.AppV1.Service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.google.common.collect.Lists;

import me.secure.AppV1.Security.AppUserRole;

@Repository("Fake")
public class FakeAppUserDaoService implements AppUserDao {

	private final PasswordEncoder passEncoder;

	@Autowired
	public FakeAppUserDaoService(PasswordEncoder passEncoder) {
		this.passEncoder = passEncoder;
	}

	@Override
	public Optional<AppUser> selectAppUserByUsername(String username) {
		return getAppUsers()
				.stream()
				.filter(AppUser -> username.equals(AppUser.getUsername()))
				.findFirst();
	}
	//Gets list of users present in database
	private List<AppUser> getAppUsers(){
		List<AppUser> AppUsers = Lists.newArrayList(
				new AppUser("Abi",
						passEncoder.encode("password"),
						AppUserRole.STUDENT.getGrantedAuthorities(),
						true, true, true, true)
				,
				new AppUser("Tom",
						passEncoder.encode("password"),
						AppUserRole.ADMINTRAINEE.getGrantedAuthorities(),
						true, true, true, true)
				,
				new AppUser("Jack",
						passEncoder.encode("password"),
						AppUserRole.ADMIN.getGrantedAuthorities(),
						true, true, true, true)
				);
		return AppUsers;
	}

}
