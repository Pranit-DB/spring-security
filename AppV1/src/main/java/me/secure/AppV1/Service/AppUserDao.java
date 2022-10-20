package me.secure.AppV1.Service;
//this interface will load the Users from data source
//We can use dependency injection to switch implementation
//if we switch database(eg.,Postgres->MongoDb) you need to change barely a single line of code
import java.util.Optional;

public interface AppUserDao {

	Optional<AppUser> selectAppUserByUsername(String username);
}
