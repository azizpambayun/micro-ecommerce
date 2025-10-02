package com.mecm.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthServiceApplication.class, args);
        System.out.println("\n" +
                "========================================\n" +
                "  JWT Authentication Service Started   \n" +
                "========================================\n" +
                "  Server: http://localhost:8081        \n" +
                "  Context Path: /api                   \n" +
                "  H2 Console: http://localhost:8081/h2-console \n" +
                "                                        \n" +
                "  Available Endpoints:                 \n" +
                "  POST /api/auth/register              \n" +
                "  POST /api/auth/login                 \n" +
                "  GET  /api/auth/me                    \n" +
                "  POST /api/auth/refresh               \n" +
                "  POST /api/auth/logout                \n" +
                "  POST /api/auth/change-password       \n" +
                "  GET  /api/auth/health                \n" +
                "                                        \n" +
                "  Test Endpoints:                      \n" +
                "  GET  /api/user/profile               \n" +
                "  GET  /api/admin/users                \n" +
                "  GET  /api/public/info                \n" +
                "========================================\n"
        );
	}

}
