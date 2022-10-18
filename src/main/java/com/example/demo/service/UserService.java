package com.example.demo.service;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.demo.dao.RoleDao;
import com.example.demo.dao.UserDao;
import com.example.demo.entity.Role;
import com.example.demo.entity.User;

@Service
public class UserService {
	
	@Autowired
	private UserDao userDao;
	
	@Autowired
	private RoleDao roleDao;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	public User registerNewUser(User user) {
		
		Role role = roleDao.findById("User").get();
		
		Set<Role> roles = new HashSet<>();
		roles.add(role);
		user.setRole(roles);
		
		user.setUserPassword(getEncodedPassword(user.getUserPassword()));
		return userDao.save(user);
	}
	
	public void initRolesAndUser() {
		Role adminRole = new Role();
		adminRole.setRoleName("ADMIN");
		adminRole.setRoleDescription("Admin Role");
		roleDao.save(adminRole);
		
		Role userRole = new Role();
		userRole.setRoleName("USER");
		userRole.setRoleDescription("Default Role for new user");
		roleDao.save(userRole);
		
		User adminUser = new User();
		adminUser.setUserFirstName("admin");
		adminUser.setUserLastName("admin");
		adminUser.setUserName("admin123");
		adminUser.setUserPassword(getEncodedPassword("admin@123"));
		Set<Role> adminRoles = new HashSet<>();
		adminRoles.add(adminRole);
		adminUser.setRole(adminRoles);
		userDao.save(adminUser);
		
//		User user = new User();
//		user.setUserFirstName("Akash");
//		user.setUserLastName("Kumar");
//		user.setUserName("akash123");
//		user.setUserPassword(getEncodedPassword("akash@123"));
//		Set<Role> userRoles = new HashSet<>();
//		userRoles.add(userRole);
//		user.setRole(userRoles);
//		userDao.save(user);
	}
	
	public String getEncodedPassword(String password) {
		return passwordEncoder.encode(password);
	}
}
