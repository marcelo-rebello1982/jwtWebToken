package br.com.cadastroit.services.config;

import static org.springframework.security.config.Customizer.withDefaults;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.bson.UuidRepresentation;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.connection.SslSettings;

import br.com.cadastroit.services.OsDetect;
import br.com.cadastroit.services.bootstrap.UserDataLoader;
import br.com.cadastroit.services.config.security.RestHeaderAuthFilter;
import br.com.cadastroit.services.config.security.RestUrlAuthFilter;
import br.com.cadastroit.services.crypt.CryptBean;
import br.com.cadastroit.services.security.domain.Authority;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@SuppressWarnings("deprecation")

public class SecurityConfig extends WebSecurityConfigurerAdapter  {
	
	private String HOST_FILE = "/opt/st-mongo-config/nosql-security.properties";
	private String pathFilter = System.getenv("pathFilter") != null ? System.getenv("pathFilter") : "administracao" ;
	private String username = System.getenv("NOSQL_USERNAME_SECURITY") != null ? System.getenv("NOSQL_USERNAME_SECURITY") : "" ;
	private String password = System.getenv("NOSQL_PASSWORD_SECURITY") != null ? System.getenv("NOSQL_PASSWORD_SECURITY") : "" ;
	private String host = System.getenv("NOSQL_HOST_MONGO_SECURITY") != null ? System.getenv("NOSQL_HOST_MONGO_SECURITY") : "" ;
	private String database = System.getenv("NOSQL_DATABASE_SECURITY") != null ? System.getenv("NOSQL_DATABASE_SECURITY") : "" ;
	private int port = System.getenv("NOSQL_HOST_PORT_MONGODB") != null ? Integer.parseInt(System.getenv("NOSQL_HOST_PORT_MONGODB")) : 0 ;
	
	 // https://github.com/giuliana-bezerra/spring-security-jwt/tree/main/src/main/resources
  	 //  https://github.com/natanaelsc/spring-boot-3-jwt-security/blob/main/src/main/java/br/com/security/config/ApplicationConfig.java
	
	
	 // este aqui
	 // https://medium.com/@Lakshitha_Fernando/jwt-spring-security-6-and-spring-boot-3-with-simple-project-819d84e09af2

    @Order(1)
    @Bean
    public MongoTemplate mongoTemplate() throws Exception{
    	
    	if(OsDetect.OS_NAME().contains("windows")) HOST_FILE = "C:\\Workspace\\st-mongo-config\\nosql-security.properties\\";
		
		if(System.getenv("NOSQL_DATABASE_SECURITY") != null) database = new String(Base64.getDecoder().decode(System.getenv("NOSQL_DATABASE_SECURITY")));
    	
		if(System.getenv("NOSQL_HOST_MONGO_SECURITY") != null) host = new String(Base64.getDecoder().decode(System.getenv("NOSQL_HOST_MONGO_SECURITY")));
		
		if(System.getenv("NOSQL_USERNAME_SECURITY") != null) username = new String(Base64.getDecoder().decode(System.getenv("NOSQL_USERNAME_SECURITY")));
	
		if(System.getenv("NOSQL_PASSWORD_SECURITY") != null) password = new String(Base64.getDecoder().decode(System.getenv("NOSQL_PASSWORD_SECURITY")));
	
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
            				.minSize(20)
            				.maxWaitTime(60, TimeUnit.SECONDS)
            				.maxConnectionLifeTime(55, TimeUnit.SECONDS)
            				.maxConnectionIdleTime(50, TimeUnit.SECONDS)
            				.build();
            		}).uuidRepresentation(UuidRepresentation.STANDARD)
            		.build();
            MongoClient client = MongoClients.create(settings);
            return new MongoTemplate(client, database);
        }catch (Exception ex){
            throw new Exception(String.format("Error on mongoClient, [error] = %s",ex.getMessage()));
        }
    }

    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder(12);
    }
    
    @Bean
    public CryptBean cryptBean() {
        CryptBean cryptBean = new CryptBean();
        cryptBean.setPasswordEncoder(encoder());
        return cryptBean;
    }
    
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
    	
        String[] roles = this.upUsersAndRolesToSecurity();

        httpSecurity.addFilterBefore(restHeaderAuthFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(restUrlAuthFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class)
                .csrf(csrf -> csrf.ignoringAntMatchers("/" + pathFilter + "/**"));
//                    .and().cors().disable();
        httpSecurity.authorizeRequests(requests -> {
        	requests
        		.antMatchers("/eureka/**",
        				"/login",
        				"/webjars/**",
        				"/swagger-resources/**",
        				"/swagger-ui.html",
        				"/swagger-ui.html/**",
        				"/v2/api-docs")
        		.permitAll()
                .antMatchers("/" + pathFilter + "/**")
                .hasAnyRole(roles);
        	}).authorizeRequests(requests ->
        		requests
                .anyRequest().authenticated())
                .formLogin(withDefaults())
                .httpBasic(withDefaults());
        httpSecurity.headers(headers -> headers.frameOptions().sameOrigin());
    }
    
  private String[] upUsersAndRolesToSecurity() throws Exception {
    	
        try{
        	
        	AtomicInteger pos = new AtomicInteger(0);
            UserDataLoader dataLoader = new UserDataLoader(this.mongoTemplate(),this.encoder());
            dataLoader.createRoles();
            List<Authority> authorities = this.mongoTemplate().findAll(Authority.class);
            String[] roles = new String[authorities.size()];

            authorities.forEach(a -> {
            	
                roles[pos.get()] = a.getRole().replace("ROLE_","");
                pos.incrementAndGet();
                
            });
            return roles;
            
        }catch (Exception ex){
            throw new Exception(String.format("Erro na leitura das regras e definicoes dos usuarios, [Error] = %s", ex.getLocalizedMessage()));
        }
    }
  
  private RestHeaderAuthFilter restHeaderAuthFilter(AuthenticationManager authenticationManager){
      RestHeaderAuthFilter filter = new RestHeaderAuthFilter(new AntPathRequestMatcher("/"+pathFilter+"/**"));
      filter.setAuthenticationManager(authenticationManager);
      return filter;
  }

  private RestUrlAuthFilter restUrlAuthFilter(AuthenticationManager authenticationManager){
      RestUrlAuthFilter filter = new RestUrlAuthFilter(new AntPathRequestMatcher("/"+pathFilter+"/**"));
      filter.setAuthenticationManager(authenticationManager);
      return filter;
  }
}
