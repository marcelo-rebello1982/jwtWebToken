package br.com.cadastroit.services.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import org.bson.UuidRepresentation;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.connection.SslSettings;

import br.com.cadastroit.services.OsDetect;
import br.com.cadastroit.services.config.security.TokenAuthenticationEntryPoint;
import br.com.cadastroit.services.config.security.TokenRequestFilter;
import br.com.cadastroit.services.config.security.TokenUserDetailsService;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private String HOST_FILE = "/opt/st-mongo-config/nosql-security.properties";
	private String pathFilter = System.getenv("pathFilter") != null ? System.getenv("pathFilter") : "administracao" ;
	private String username = System.getenv("NOSQL_USERNAME_SECURITY") != null ? System.getenv("NOSQL_USERNAME_SECURITY") : "" ;
	private String password = System.getenv("NOSQL_PASSWORD_SECURITY") != null ? System.getenv("NOSQL_PASSWORD_SECURITY") : "" ;
	private String host = System.getenv("NOSQL_HOST_MONGO_SECURITY") != null ? System.getenv("NOSQL_HOST_MONGO_SECURITY") : "" ;
	private String database = System.getenv("NOSQL_DATABASE_SECURITY") != null ? System.getenv("NOSQL_DATABASE_SECURITY") : "" ;
	private int port = System.getenv("NOSQL_HOST_PORT_MONGODB") != null ? Integer.parseInt(System.getenv("NOSQL_HOST_PORT_MONGODB")) : 0 ;

    private TokenUserDetailsService tokenUserDetailsService;

    @Order(1)
    @Bean
    public MongoTemplate mongoTemplate() throws Exception {
    	
    	if(OsDetect.OS_NAME().contains("windows")) HOST_FILE = "C:\\Workspace\\st-mongo-config\\nosql-security.properties\\";
		
    	if(System.getenv("NOSQL_DATABASE_SECURITY") != null) {
			database = new String(Base64.getDecoder().decode(System.getenv("NOSQL_DATABASE_SECURITY")));
		}
		if(System.getenv("NOSQL_HOST_MONGO_SECURITY") != null) {
			host = new String(Base64.getDecoder().decode(System.getenv("NOSQL_HOST_MONGO_SECURITY")));
		}
		if(System.getenv("NOSQL_USERNAME_SECURITY") != null) {
			username = new String(Base64.getDecoder().decode(System.getenv("NOSQL_USERNAME_SECURITY")));
		}
		if(System.getenv("NOSQL_PASSWORD_SECURITY") != null) {
			password = new String(Base64.getDecoder().decode(System.getenv("NOSQL_PASSWORD_SECURITY")));
		}
		if(System.getenv("NOSQL_DATABASE_SECURITY") == null) {
			File resourceConnection = new File(HOST_FILE);
			Properties properties = new Properties();
			try(InputStream in = new FileInputStream(resourceConnection)){
				properties.load(in);
				host	 = new String(Base64.getDecoder().decode(properties.getProperty("NOSQL_HOST_MONGO_SECURITY")));
				database = new String(Base64.getDecoder().decode(properties.getProperty("NOSQL_DATABASE_SECURITY")));
				port	 = Integer.parseInt(properties.getProperty("NOSQL_HOST_PORT_MONGODB"));
				username = new String(Base64.getDecoder().decode(properties.getProperty("NOSQL_USERNAME_SECURITY")));
				password = new String(Base64.getDecoder().decode(properties.getProperty("NOSQL_PASSWORD_SECURITY")));
			} catch (IOException ex) {
				System.out.println("Error on read application.properties, [Error] = " + ex.getMessage());
			}
		}
    	
        try {
        	
            MongoClientSettings settings = MongoClientSettings
            		.builder()
            		.applyToSslSettings(ssl -> {
            			ssl.applySettings(SslSettings.builder()
            					.enabled(false)
            						.build());
            }).applyConnectionString(new ConnectionString("mongodb://"+username+":"+password+"@"+host+":"+port))
                    .applyToConnectionPoolSettings(pool -> {
                    		pool
                    		.maxSize(50)
                    		.maxWaitTime(60, TimeUnit.SECONDS)
                    		.maxConnectionLifeTime(55, TimeUnit.SECONDS)
                    		.maxConnectionIdleTime(50, TimeUnit.SECONDS)
                    		.minSize(20)
                    		.build();
            }).uuidRepresentation(UuidRepresentation.STANDARD).build();
            MongoClient client = MongoClients.create(settings);
            return new MongoTemplate(client, database);
        }catch (Exception ex){
            throw new Exception(String.format("Error on mongoClient, [error] = %s",ex.getMessage()));
        }
    }

    @Bean
    public PasswordEncoder encoder(){
        return new BCryptPasswordEncoder(12);
    }

    private TokenRequestFilter tokenRequestFilter() throws Exception{
        if(this.tokenUserDetailsService == null){
            this.tokenUserDetailsService = TokenUserDetailsService.builder().mongoTemplate(this.mongoTemplate()).build();
        }
        return TokenRequestFilter.builder().mongoTemplate(this.mongoTemplate()).build();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.ignoringAntMatchers("/" + pathFilter + "/**"));
        http.addFilterBefore(this.tokenRequestFilter(), UsernamePasswordAuthenticationFilter.class);
        http.authorizeRequests(requests -> 
        		requests
                	.antMatchers("/eureka/**",
                        "/login",
                        "/webjars/**",
                        "/swagger-resources/**",
                        "/swagger-ui.html",
                        "/swagger-ui.html/**",
                        "/v2/api-docs")
                	.permitAll())
        			.authorizeRequests(requests -> 
       			requests
        			.antMatchers(HttpMethod.POST,
   					"/" + pathFilter + "/auth/user/create/**",
   					"/" + pathFilter + "/auth/user/recovery/token",
   					"/" + pathFilter + "/auth/user/update/token",
   					"/" + pathFilter + "/auth/user/update/password",
   					"/" + pathFilter + "/auth/user/request/token",
   					"/" + pathFilter + "/auth/user/crypt/password",
   					"/" + pathFilter + "/auth/user/decrypt/password",
   					"/" + pathFilter + "/auth/user/token/**")
        			.permitAll())
        			.authorizeRequests(requests -> 
       			requests
            			.antMatchers(HttpMethod.DELETE,
       					"/" + pathFilter + "/auth/user/remove/user")
            			.permitAll())
        			.authorizeRequests(requests -> 
   				requests
       				.anyRequest()
       				.authenticated())
        			.exceptionHandling(handling -> 
                handling
                	.authenticationEntryPoint(TokenAuthenticationEntryPoint.builder().build()))
        			.sessionManagement(management ->
               	management
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
    }
}
