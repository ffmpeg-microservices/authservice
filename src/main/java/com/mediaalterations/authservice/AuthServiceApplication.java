package com.mediaalterations.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableFeignClients
public class AuthServiceApplication {

	//postgres time zone is Asia/Kolkata and JVM default time zone was
	// taking Asia/Calcutta, so in run configurations we need to add this,
	// -Duser.timezone=Asia/Kolkata

	// remeber to add in in docker too, java -Duser.timezone=Asia/Kolkata -jar your-application.jar

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
	}

}
