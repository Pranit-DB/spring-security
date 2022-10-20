package me.secure.AppV1.Jwt;

public class UnameAndPassAuthRequest {

	private String username;
	private String password;

	public UnameAndPassAuthRequest() {
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

}
